/**
 * Fine Elements — S3 adapters for the master backup lane (relocated from
 * the private source repository, S12K-D2).
 *
 * Three adapters, one per credential, each issuing only the commands its
 * credential is meant for:
 *
 *   B2RestoreReader   ListObjectVersions, GetObject by exact VersionId
 *   B2MinimalWriter   PutObject
 *   R2MasterSource    GetObject on the private R2 bucket
 *
 * The lane has no other B2 or R2 operation, by construction.
 */

import {
  GetObjectCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';

import { bodyToBytes } from '../lib/body.ts';
import {
  assertBackupTarget,
  type B2VersionEntry,
  type BackupObjectWriter,
  type BackupTarget,
  type BackupVersionReader,
  type MasterSourceReader,
  type ObservedVersion,
} from './master-backup-lane.ts';

export interface S3Credentials {
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
}

/**
 * The B2 client. Checksum behaviour is isolated here: Backblaze's S3 API does
 * not accept the SDK's default flexible-checksum trailers, so checksums are
 * computed and validated only when an operation requires them. Integrity
 * comes from Content-MD5 on PUT and the exact-version SHA-256 readback.
 */
export function createB2Client(
  target: BackupTarget,
  credentials: S3Credentials,
  options: { readonly maxAttempts?: number } = {},
): S3Client {
  assertBackupTarget(target);
  return new S3Client({
    endpoint: target.b2Endpoint,
    region: target.b2Region,
    credentials: {
      accessKeyId: requireNonBlank(credentials.accessKeyId, 'accessKeyId'),
      secretAccessKey: requireNonBlank(credentials.secretAccessKey, 'secretAccessKey'),
    },
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    ...(options.maxAttempts === undefined ? {} : { maxAttempts: options.maxAttempts }),
  });
}

/**
 * The writer's client never retries inside the SDK: a retried PutObject
 * could create a second version. A failed PUT is left to the next verify-scan.
 */
export function createB2WriterClient(target: BackupTarget, credentials: S3Credentials): S3Client {
  return createB2Client(target, credentials, { maxAttempts: 1 });
}

const CLOUDFLARE_ACCOUNT_ID = /^[0-9a-f]{32}$/;

/**
 * The R2 source endpoint is derived ONLY from the Cloudflare account ID, so
 * no other host can receive the R2 source credential.
 */
export function createR2SourceClient(config: {
  readonly accountId: string;
  readonly credentials: S3Credentials;
}): S3Client {
  if (!CLOUDFLARE_ACCOUNT_ID.test(config.accountId)) {
    throw new TypeError('accountId must be a 32-character lowercase hex Cloudflare account ID');
  }
  return new S3Client({
    region: 'auto',
    endpoint: `https://${config.accountId}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: requireNonBlank(config.credentials.accessKeyId, 'accessKeyId'),
      secretAccessKey: requireNonBlank(config.credentials.secretAccessKey, 'secretAccessKey'),
    },
  });
}

export class B2RestoreReader implements BackupVersionReader {
  readonly #client: S3Client;
  readonly #bucket: string;

  constructor(client: S3Client, target: BackupTarget) {
    this.#client = client;
    this.#bucket = assertBackupTarget(target).b2Bucket;
  }

  async listVersions(prefix: string): Promise<readonly B2VersionEntry[]> {
    requireNonBlank(prefix, 'prefix');
    const entries: B2VersionEntry[] = [];
    let keyMarker: string | undefined;
    let versionIdMarker: string | undefined;
    for (let page = 0; page < 10_000; page += 1) {
      const out = await this.#client.send(new ListObjectVersionsCommand({
        Bucket: this.#bucket,
        Prefix: prefix,
        KeyMarker: keyMarker,
        VersionIdMarker: versionIdMarker,
      }));
      for (const version of out.Versions ?? []) {
        entries.push({ key: requireNonBlank(version.Key ?? '', 'Versions[].Key'), versionId: requireNonBlank(version.VersionId ?? '', 'Versions[].VersionId'), kind: 'version' });
      }
      for (const marker of out.DeleteMarkers ?? []) {
        entries.push({ key: requireNonBlank(marker.Key ?? '', 'DeleteMarkers[].Key'), versionId: requireNonBlank(marker.VersionId ?? '', 'DeleteMarkers[].VersionId'), kind: 'delete_marker' });
      }
      if (out.IsTruncated !== true) return entries;
      keyMarker = out.NextKeyMarker;
      versionIdMarker = out.NextVersionIdMarker;
      if (keyMarker === undefined || keyMarker === '') {
        throw new Error('ListObjectVersions was truncated without a continuation marker');
      }
    }
    throw new Error('ListObjectVersions did not terminate');
  }

  async getVersion(key: string, versionId: string): Promise<ObservedVersion | null> {
    try {
      const out = await this.#client.send(new GetObjectCommand({
        Bucket: this.#bucket,
        Key: requireNonBlank(key, 'key'),
        VersionId: requireNonBlank(versionId, 'versionId'),
      }));
      if (out.Body === undefined) throw new Error('B2 returned an object version without a body');
      return { bytes: await bodyToBytes(out.Body), versionId: out.VersionId ?? null };
    } catch (error) {
      // Only an explicit "no such key/version" is definitive. Anything else
      // (403, NoSuchBucket, 5xx, network) propagates as indeterminate.
      if (error instanceof Error && (error.name === 'NoSuchKey' || error.name === 'NoSuchVersion')) return null;
      throw error;
    }
  }
}

export class B2MinimalWriter implements BackupObjectWriter {
  readonly #client: S3Client;
  readonly #bucket: string;
  readonly #keyPrefix: string;

  constructor(client: S3Client, target: BackupTarget) {
    this.#client = client;
    this.#bucket = assertBackupTarget(target).b2Bucket;
    this.#keyPrefix = `${target.destinationPrefix}masters/`;
  }

  async putObject(input: {
    readonly key: string;
    readonly bytes: Uint8Array;
    readonly contentMd5Base64: string;
    readonly contentType: string;
  }): Promise<{ readonly versionId: string | null }> {
    if (!input.key.startsWith(this.#keyPrefix)) throw new Error('refusing a PUT outside the target masters/ prefix');
    const out = await this.#client.send(new PutObjectCommand({
      Bucket: this.#bucket,
      Key: input.key,
      Body: input.bytes,
      ContentLength: input.bytes.byteLength,
      ContentMD5: requireNonBlank(input.contentMd5Base64, 'contentMd5Base64'),
      ContentType: requireNonBlank(input.contentType, 'contentType'),
    }));
    return { versionId: typeof out.VersionId === 'string' && out.VersionId.trim() !== '' ? out.VersionId : null };
  }
}

export class R2MasterSource implements MasterSourceReader {
  readonly #client: S3Client;
  readonly #bucket: string;

  constructor(client: S3Client, target: BackupTarget) {
    this.#client = client;
    this.#bucket = assertBackupTarget(target).sourceBucket;
  }

  async getMaster(masterKey: string): Promise<{ readonly bytes: Uint8Array; readonly contentType: string | null } | null> {
    try {
      const out = await this.#client.send(new GetObjectCommand({ Bucket: this.#bucket, Key: requireNonBlank(masterKey, 'masterKey') }));
      if (out.Body === undefined) throw new Error('R2 returned a master without a body');
      return { bytes: await bodyToBytes(out.Body), contentType: out.ContentType ?? null };
    } catch (error) {
      if (error instanceof Error && error.name === 'NoSuchKey') return null;
      throw error;
    }
  }
}

function requireNonBlank(value: string, label: string): string {
  if (value.trim() === '') throw new TypeError(`${label} must be a non-blank string`);
  return value;
}
