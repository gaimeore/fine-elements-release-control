/**
 * Deployment entry point, one mode per job of deploy-<target>.yml:
 *
 *   select   (deploy-prepare)  DB deploy_runner + R2 deploy reader
 *   deploy   (deploy)          DB deploy_runner + Cloudflare deploy token
 *   verify   (verify)          DB deploy_runner + Cloudflare read token
 *
 * Every mode: credential-family check, production-release run, verified
 * TARGET_CONFIG_JSON, live DB identity — all before any mutation. Inputs
 * cross jobs only as handoffs sealed to the consuming environment and bound
 * to this run, attempt, manifest sequence and source commit. The public log
 * gets fixed tokens only.
 */
import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';

import { bodyToBytes } from '../lib/body.ts';
import { assertDatabaseIdentity, createPgDatabase } from '../lib/db.ts';
import { FailClosedError } from '../lib/errors.ts';
import { assertReleaseRun, runContextFrom, setStepOutput, status, type RunContext } from '../lib/github.ts';
import type { HandoffContext } from '../lib/handoff.ts';
import { checkJobEnv, requireEnv } from '../lib/job-env.ts';
import { parseManifest, type ReleaseManifest } from '../lib/manifest.ts';
import { loadRecipientTable, readHandoff, recipientsFor, writeHandoff } from '../lib/recipients.ts';
import { loadFingerprintTable, parseTarget, verifiedTargetConfig, type Target } from '../lib/target-config.ts';
import { createR2SourceClient } from '../backup/s3-backup-adapters.ts';
import { injectRenditions, placementsFromSnapshot, sha256Hex, type RenditionPlacement } from './placements.ts';
import { unpackBundle, validateBundleTree } from './bundle.ts';
import { runDeploy, runVerify, selectWork, type ClaimRecord, type PreviousLiveEvidence } from './orchestrator.ts';
import { CloudflareWorkersDeploymentProvider } from './provider.ts';
import { findLatestSucceeded, findPublication } from './repository.ts';

export type DeployMode = 'select' | 'deploy' | 'verify';

function context(run: RunContext, target: Target, manifest: ReleaseManifest, producerJob: string, artifact: string): HandoffContext {
  return {
    repository: run.repository, workflowRef: run.workflowRef, target, runId: run.runId, runAttempt: run.runAttempt, producerJob, artifact,
    bindings: { manifest_sequence: String(manifest.sequence), source_commit: manifest.source_commit },
  };
}

async function getObject(client: S3Client, bucket: string, key: string): Promise<Uint8Array> {
  const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  if (out.Body === undefined) throw new FailClosedError('an R2 object has no body');
  return bodyToBytes(out.Body);
}

export function parseClaim(value: unknown): ClaimRecord {
  const raw = value as Record<string, unknown>;
  const mode = raw?.mode;
  if (typeof raw !== 'object' || raw === null || (mode !== 'fresh' && mode !== 'resolve')) throw new FailClosedError('claim record is malformed');
  for (const key of ['attemptId', 'publicationId', 'claimedAt', 'sourceCommit']) {
    if (typeof raw[key] !== 'string' || raw[key] === '') throw new FailClosedError('claim record is malformed');
  }
  return raw as unknown as ClaimRecord;
}

/** null only when select found no earlier succeeded attempt (verify then fails closed). */
export function parsePreviousLive(value: unknown): PreviousLiveEvidence | null {
  if (value === null) return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new FailClosedError('previous live evidence is malformed');
  for (const key of ['attempt_id', 'publication_id', 'provider_version_id', 'snapshot_sha256', 'snapshot_b64']) {
    if (typeof raw[key] !== 'string' || raw[key] === '') throw new FailClosedError('previous live evidence is malformed');
  }
  return {
    attemptId: raw.attempt_id as string,
    publicationId: raw.publication_id as string,
    providerVersionId: raw.provider_version_id as string,
    snapshotSha256: raw.snapshot_sha256 as string,
    snapshot: new Uint8Array(Buffer.from(raw.snapshot_b64 as string, 'base64')),
  };
}

async function select(env: NodeJS.ProcessEnv, run: RunContext, target: Target, manifest: ReleaseManifest): Promise<number> {
  checkJobEnv('deploy-prepare', env);
  const config = verifiedTargetConfig(env.TARGET_CONFIG_JSON, 'deploy-prepare', target, loadFingerprintTable());
  const recipients = loadRecipientTable();
  const db = createPgDatabase(requireEnv(env, 'DEPLOY_RUNNER_DATABASE_URL'));
  try {
    await assertDatabaseIdentity(db, config);
    const selection = await selectWork(db, manifest, env.FE_DEPLOY_PAUSED === 'true');
    if (selection.mode === 'none' || selection.mode === 'attention') {
      setStepOutput(env, 'mode', selection.mode);
      status(selection.mode === 'none' ? 'FE_DEPLOY_SELECT=NONE' : 'FE_DEPLOY_SELECT=ATTENTION', { reason: selection.reason });
      return selection.mode === 'none' ? 0 : 1;
    }
    const job = selection.job;
    const publication = await findPublication(db, job.publicationId);
    if (publication === null) throw new FailClosedError('the job publication is missing');
    const r2 = createR2SourceClient({
      accountId: config.fields.cloudflare_account_id!,
      credentials: { accessKeyId: requireEnv(env, 'R2_DEPLOY_READER_ACCESS_KEY_ID'), secretAccessKey: requireEnv(env, 'R2_DEPLOY_READER_SECRET_ACCESS_KEY') },
    });
    const bucket = config.fields.r2_private_media_bucket!;
    const snapshot = await getObject(r2, bucket, publication.snapshotKey);
    if (sha256Hex(snapshot) !== publication.contentHash || publication.snapshotKey !== `snapshots/${publication.contentHash}.json`) {
      throw new FailClosedError('publication snapshot does not match its content hash');
    }
    const placements = placementsFromSnapshot(snapshot);
    const renditions: Record<string, string> = {};
    for (const placement of placements) {
      const bytes = await getObject(r2, bucket, placement.renditionKey);
      if (sha256Hex(bytes) !== placement.sha256) throw new FailClosedError('a rendition does not match its snapshot hash');
      renditions[placement.renditionKey] = Buffer.from(bytes).toString('base64');
    }
    // The publication live before this attempt; verify re-binds it to the ledger and proves its retired renditions absent.
    const previous = await findLatestSucceeded(db);
    let previousLive: Record<string, string> | null = null;
    if (previous !== null) {
      const prior = await findPublication(db, previous.publicationId);
      if (prior === null) throw new FailClosedError('the previous live publication is missing');
      const priorSnapshot = await getObject(r2, bucket, prior.snapshotKey);
      if (sha256Hex(priorSnapshot) !== prior.contentHash || prior.snapshotKey !== `snapshots/${prior.contentHash}.json`) {
        throw new FailClosedError('previous live publication snapshot does not match its content hash');
      }
      previousLive = {
        attempt_id: previous.attemptId, publication_id: previous.publicationId, provider_version_id: previous.providerVersionId,
        snapshot_sha256: prior.contentHash, snapshot_b64: Buffer.from(priorSnapshot).toString('base64'),
      };
    }
    const claim: ClaimRecord = { attemptId: job.attemptId, publicationId: job.publicationId, claimedAt: job.claimedAt!, sourceCommit: job.sourceCommit!, mode: selection.mode };
    const json = (value: unknown): Buffer => Buffer.from(JSON.stringify(value), 'utf8');
    const out = (name: string): string => path.join(requireEnv(env, 'FE_HANDOFF_DIR'), `${name}.fehandoff`);
    setStepOutput(env, 'build_input_digest', writeHandoff(out('build-input'), json({
      schema: 'fe-build-input/1', source_commit: manifest.source_commit, manifest_sequence: manifest.sequence,
      snapshot_b64: Buffer.from(snapshot).toString('base64'), snapshot_sha256: publication.contentHash,
    }), recipientsFor(recipients, target, ['build']), context(run, target, manifest, 'select-claim-prepare', 'build-input')));
    setStepOutput(env, 'deploy_input_digest', writeHandoff(out('deploy-input'), json({
      schema: 'fe-deploy-input/1', claim, snapshot_sha256: publication.contentHash, placements, renditions,
    }), recipientsFor(recipients, target, ['deploy']), context(run, target, manifest, 'select-claim-prepare', 'deploy-input')));
    setStepOutput(env, 'verify_input_digest', writeHandoff(out('verify-input'), json({
      schema: 'fe-verify-input/2', claim, placements, previous_live: previousLive,
    }), recipientsFor(recipients, target, ['verify']), context(run, target, manifest, 'select-claim-prepare', 'verify-input')));
    setStepOutput(env, 'mode', selection.mode);
    status(selection.mode === 'fresh' ? 'FE_DEPLOY_SELECT=FRESH' : 'FE_DEPLOY_SELECT=RESOLVE', { renditions: placements.length });
    return 0;
  } finally {
    await db.close();
  }
}

async function deploy(env: NodeJS.ProcessEnv, run: RunContext, target: Target, manifest: ReleaseManifest): Promise<number> {
  checkJobEnv('deploy', env);
  const config = verifiedTargetConfig(env.TARGET_CONFIG_JSON, 'deploy', target, loadFingerprintTable());
  const key = requireEnv(env, 'FE_HANDOFF_PRIVATE_KEY');
  const dir = requireEnv(env, 'FE_HANDOFF_DIR');
  const input = JSON.parse(readHandoff(path.join(dir, 'deploy-input.fehandoff'), env.DEPLOY_INPUT_DIGEST, key, context(run, target, manifest, 'select-claim-prepare', 'deploy-input')).toString('utf8')) as Record<string, unknown>;
  const built = JSON.parse(readHandoff(path.join(dir, 'bundle.fehandoff'), env.BUNDLE_DIGEST, key, context(run, target, manifest, 'build', 'bundle')).toString('utf8')) as Record<string, unknown>;
  if (input.schema !== 'fe-deploy-input/1') throw new FailClosedError('deploy input is malformed');
  const claim = parseClaim(input.claim);
  if (claim.sourceCommit !== manifest.source_commit) throw new FailClosedError('the claim is not bound to this manifest');
  const metadata = built.metadata as Record<string, unknown>;
  const bundle = Buffer.from(String(built.bundle_b64), 'base64');
  if (metadata?.schema !== 'fe-bundle-metadata/1'
    || metadata.source_commit !== manifest.source_commit
    || metadata.source_archive_sha256 !== manifest.source_archive_sha256
    || metadata.migration_ceiling !== manifest.migration_ceiling
    || metadata.manifest_sequence !== manifest.sequence
    || metadata.snapshot_sha256 !== input.snapshot_sha256
    || metadata.bundle_sha256 !== sha256Hex(bundle)
    || metadata.bundle_bytes !== bundle.length) {
    throw new FailClosedError('bundle metadata does not match the manifest and prepared inputs');
  }
  const placements = input.placements as RenditionPlacement[];
  const renditions = new Map(Object.entries(input.renditions as Record<string, string>).map(([k, v]) => [k, new Uint8Array(Buffer.from(v, 'base64'))]));
  const bundleDir = mkdtempSync(path.join(env.RUNNER_TEMP ?? tmpdir(), 'fe-bundle-'));
  const db = createPgDatabase(requireEnv(env, 'DEPLOY_RUNNER_DATABASE_URL'));
  try {
    await assertDatabaseIdentity(db, config);
    unpackBundle(bundle, bundleDir);
    validateBundleTree(bundleDir, 'forbidden');
    injectRenditions(bundleDir, placements, renditions);
    validateBundleTree(bundleDir, 'allowed');
    const provider = new CloudflareWorkersDeploymentProvider({
      accountId: config.fields.cloudflare_account_id!,
      workerName: config.fields.public_worker_name!,
      wranglerBin: path.resolve('node_modules', '.bin', process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler'),
    });
    const outcome = await runDeploy({ db, provider, environment: config.fields.deployment_environment_label!, bundleDir }, claim);
    status(`FE_DEPLOY=${outcome.status.toUpperCase()}`, 'reason' in outcome ? { reason: outcome.reason.replace(/[^a-z_]/g, '_') } : {});
    return outcome.status === 'succeeded' ? 0 : 1;
  } finally {
    await db.close();
    rmSync(bundleDir, { recursive: true, force: true });
  }
}

async function verify(env: NodeJS.ProcessEnv, run: RunContext, target: Target, manifest: ReleaseManifest): Promise<number> {
  checkJobEnv('deploy-verify', env);
  const config = verifiedTargetConfig(env.TARGET_CONFIG_JSON, 'verify', target, loadFingerprintTable());
  const key = requireEnv(env, 'FE_HANDOFF_PRIVATE_KEY');
  const dir = requireEnv(env, 'FE_HANDOFF_DIR');
  const input = JSON.parse(readHandoff(path.join(dir, 'verify-input.fehandoff'), env.VERIFY_INPUT_DIGEST, key, context(run, target, manifest, 'select-claim-prepare', 'verify-input')).toString('utf8')) as Record<string, unknown>;
  const files = JSON.parse(readHandoff(path.join(dir, 'bundle-files.fehandoff'), env.BUNDLE_FILES_DIGEST, key, context(run, target, manifest, 'build', 'bundle-files')).toString('utf8')) as { files: { path: string; sha256: string }[] };
  if (input.schema !== 'fe-verify-input/2' || !('previous_live' in input)) throw new FailClosedError('verify input is malformed');
  const claim = parseClaim(input.claim);
  const previousLive = parsePreviousLive(input.previous_live);
  const db = createPgDatabase(requireEnv(env, 'DEPLOY_RUNNER_DATABASE_URL'));
  try {
    await assertDatabaseIdentity(db, config);
    const provider = new CloudflareWorkersDeploymentProvider({
      accountId: config.fields.cloudflare_account_id!,
      workerName: config.fields.public_worker_name!,
      wranglerBin: path.resolve('node_modules', '.bin', process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler'),
    });
    const outcome = await runVerify({
      db,
      currentDeployment: () => provider.getCurrentDeployment(),
      fetch: async (url) => {
        const response = await fetch(url, { redirect: 'manual', headers: { 'Cache-Control': 'no-cache' } });
        return { status: response.status, contentType: response.headers.get('content-type'), body: new Uint8Array(await response.arrayBuffer()) };
      },
      origin: config.fields.public_origin!,
      sha256: sha256Hex,
      notFoundProbePath: `__fe-verify-${randomUUID()}`,
    }, {
      attemptId: claim.attemptId,
      publicationId: claim.publicationId,
      placements: input.placements as RenditionPlacement[],
      files: files.files.filter((file) => ['index.html', 'robots.txt', 'sitemap.xml'].includes(file.path)),
      previousLive,
    });
    status(`FE_VERIFY=${outcome.toUpperCase()}`);
    return outcome === 'verified' || outcome === 'already_verified' ? 0 : 1;
  } finally {
    await db.close();
  }
}

export async function main(argv: readonly string[], env: NodeJS.ProcessEnv): Promise<number> {
  const mode = argv[0];
  if (mode !== 'select' && mode !== 'deploy' && mode !== 'verify') throw new FailClosedError('expected mode: select, deploy or verify');
  const target = parseTarget(env.FE_TARGET);
  const run = runContextFrom(env);
  assertReleaseRun(run);
  const manifest = parseManifest(JSON.parse(readFileSync(`release/${target}.json`, 'utf8')) as unknown, target);
  if (mode === 'select') return select(env, run, target, manifest);
  if (mode === 'deploy') return deploy(env, run, target, manifest);
  return verify(env, run, target, manifest);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2), process.env).then(
    (code) => process.exit(code),
    (error: unknown) => {
      console.error(`FE_DEPLOY_JOB=FAIL ${error instanceof FailClosedError ? `refused: ${error.message}` : `failed: ${error instanceof Error ? error.name : 'error'}`}`);
      process.exit(1);
    },
  );
}
