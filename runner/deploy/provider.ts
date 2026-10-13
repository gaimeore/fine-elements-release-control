/**
 * Public Worker provider: the Cloudflare Wrangler CLI (a pinned control
 * dependency, installed with --ignore-scripts). Ported from the private
 * source repository's accepted provider (Sprint 11C/12F semantics: tagged
 * uploads, exact-version activation, fail-closed tag resolution,
 * indeterminate states never terminalized). The generated config is trusted
 * control code: assets only, no `main`, workers_dev and preview URLs off.
 */
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

export interface UploadedPublicVersion {
  readonly providerVersionId: string;
}

export interface PublicDeploymentProvider {
  uploadVersion(
    distDir: string,
    correlationTag: string,
  ): Promise<UploadedPublicVersion>;

  // Sprint 12F — read-only lookup of a version that a previous uploadVersion
  // call already created under exactly this correlation tag. It never uploads
  // and must fail closed unless exactly one version carries the tag.
  resolveUploadedVersion(
    correlationTag: string,
  ): Promise<UploadedPublicVersion>;

  activateVersion(
    providerVersionId: string,
  ): Promise<DeploymentActivationResult>;

  // Read-only count of versions carrying exactly this correlation tag.
  countTaggedVersions(correlationTag: string): Promise<number>;

  getCurrentDeployment(): Promise<CurrentPublicDeployment | 'unknown'>;
}

export type DeploymentActivationResult =
  | {
      readonly outcome: 'accepted';
    }
  | {
      readonly outcome: 'rejected';
      readonly detail: string;
    };

export interface CurrentPublicDeployment {
  readonly versions: readonly CurrentPublicDeploymentVersion[];
}

export interface CurrentPublicDeploymentVersion {
  readonly providerVersionId: string;
  readonly percentage: number;
}

export class IndeterminateDeploymentError extends Error {
  constructor(message: string, options: { readonly cause?: unknown } = {}) {
    super(message, options);
    this.name = 'IndeterminateDeploymentError';
  }
}



export interface CommandResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface CommandRunner {
  run(
    command: string,
    args: readonly string[],
    options?: { readonly cwd?: string },
  ): Promise<CommandResult>;
}

export interface CloudflareWorkersDeploymentProviderConfig {
  readonly accountId: string;
  readonly workerName: string;
  readonly wranglerBin: string;
  readonly commandRunner?: CommandRunner;
}

const COMPATIBILITY_DATE = '2026-08-19';
const VERSION_ID_PATTERN = /^[0-9a-fA-F-]{16,128}$/;

export class CloudflareWorkersDeploymentProvider implements PublicDeploymentProvider {
  readonly #accountId: string;
  readonly #workerName: string;
  readonly #wranglerBin: string;
  readonly #commandRunner: CommandRunner;

  constructor(config: CloudflareWorkersDeploymentProviderConfig) {
    this.#accountId = requireNonBlank(config.accountId, 'accountId');
    this.#workerName = requireNonBlank(config.workerName, 'workerName');
    this.#wranglerBin = requireNonBlank(config.wranglerBin, 'wranglerBin');
    this.#commandRunner = config.commandRunner ?? new SpawnCommandRunner();
  }

  async uploadVersion(
    distDir: string,
    correlationTag: string,
  ): Promise<UploadedPublicVersion> {
    requireNonBlank(distDir, 'distDir');
    requireNonBlank(correlationTag, 'correlationTag');

    return await this.#withConfig(distDir, async (configPath) => {
      await this.#runWranglerMustSucceed([
        'versions',
        'upload',
        distDir,
        '--config',
        configPath,
        '--tag',
        correlationTag,
      ]);

      return await this.#resolveVersionByTag(configPath, correlationTag);
    });
  }

  async resolveUploadedVersion(correlationTag: string): Promise<UploadedPublicVersion> {
    requireNonBlank(correlationTag, 'correlationTag');

    return await this.#withConfig(null, async (configPath) =>
      await this.#resolveVersionByTag(configPath, correlationTag),
    );
  }

  /** Read-only: how many provider versions carry exactly this tag (recovery decisions). */
  async countTaggedVersions(correlationTag: string): Promise<number> {
    requireNonBlank(correlationTag, 'correlationTag');
    return await this.#withConfig(null, async (configPath) => {
      const list = await this.#runWranglerMustSucceed(['versions', 'list', '--config', configPath, '--json']);
      return findVersionIdsByTag(JSON.parse(list.stdout) as unknown, correlationTag).length;
    });
  }

  async activateVersion(providerVersionId: string): Promise<DeploymentActivationResult> {
    assertValidProviderVersionId(providerVersionId);
    return await this.#withConfig(null, async (configPath) => {
      const result = await this.#commandRunner.run(this.#wranglerBin, [
        'versions',
        'deploy',
        `${providerVersionId}@100`,
        '--config',
        configPath,
        '--yes',
      ]);

      if (result.exitCode === 0) {
        return { outcome: 'accepted' };
      }
      if (looksIndeterminate(result.stderr) || looksIndeterminate(result.stdout)) {
        throw new IndeterminateDeploymentError('Cloudflare version activation state is indeterminate');
      }
      return { outcome: 'rejected', detail: trimDetail(result.stderr || result.stdout) };
    });
  }

  async getCurrentDeployment(): Promise<CurrentPublicDeployment | 'unknown'> {
    return await this.#withConfig(null, async (configPath) => {
      const result = await this.#commandRunner.run(this.#wranglerBin, [
        'deployments',
        'list',
        '--config',
        configPath,
        '--json',
      ]);
      if (result.exitCode !== 0) {
        if (looksIndeterminate(result.stderr) || looksIndeterminate(result.stdout)) {
          return 'unknown';
        }
        throw new Error('Cloudflare deployments query was rejected');
      }
      return parseCurrentDeploymentJson(JSON.parse(result.stdout) as unknown);
    });
  }

  async #resolveVersionByTag(
    configPath: string,
    correlationTag: string,
  ): Promise<UploadedPublicVersion> {
    const list = await this.#runWranglerMustSucceed([
      'versions',
      'list',
      '--config',
      configPath,
      '--json',
    ]);
    const matches = findVersionIdsByTag(JSON.parse(list.stdout) as unknown, correlationTag);
    if (matches.length !== 1) {
      throw new Error(
        `Cloudflare version tag resolution failed closed: expected exactly one match, got ${matches.length}`,
      );
    }

    const providerVersionId = matches[0] as string;
    assertValidProviderVersionId(providerVersionId);
    return { providerVersionId };
  }

  async #runWranglerMustSucceed(args: readonly string[]): Promise<CommandResult> {
    const result = await this.#commandRunner.run(this.#wranglerBin, args);
    if (result.exitCode !== 0) {
      if (looksIndeterminate(result.stderr) || looksIndeterminate(result.stdout)) {
        throw new IndeterminateDeploymentError('Cloudflare Wrangler command state is indeterminate');
      }
      throw new Error('Cloudflare Wrangler command was rejected');
    }
    return result;
  }

  async #withConfig<T>(
    distDir: string | null,
    work: (configPath: string) => Promise<T>,
  ): Promise<T> {
    const dir = await mkdtemp(path.join(tmpdir(), 'fine-elements-wrangler-'));
    const configPath = path.join(dir, 'wrangler.json');
    // Sprint 11C — exposure is stated explicitly, never inherited. Every
    // generated config (versions upload, versions list, versions deploy,
    // deployments list) flows through here, so disabling both surfaces at
    // this one place is what keeps a freshly created PROD Worker from being
    // reachable — or indexable — over a workers.dev subdomain or a preview
    // URL before cutover. A Wrangler/Cloudflare default is not a guarantee:
    // it can differ per account and can change between versions, so it is
    // never relied upon (see server/RUNBOOK.md §9).
    const config: Record<string, unknown> = {
      name: this.#workerName,
      account_id: this.#accountId,
      compatibility_date: COMPATIBILITY_DATE,
      workers_dev: false,
      preview_urls: false,
    };
    if (distDir !== null) {
      // SEO-B1 (ARCHITECTURE.md §12): every canonical public route is a real
      // static HTML file generated at materialization (server/deploy/public-seo.ts),
      // so an unknown URL now gets the generated 404.html with a genuine 404
      // status instead of the SPA shell with 200, and "/a/" is served as "/a".
      // The exact Cloudflare URL behaviour is proven in TEST before PROD.
      config.assets = {
        directory: distDir,
        not_found_handling: '404-page',
        html_handling: 'drop-trailing-slash',
      };
    }

    try {
      await writeFile(configPath, JSON.stringify(config), 'utf8');
      return await work(configPath);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}

export class SpawnCommandRunner implements CommandRunner {
  async run(command: string, args: readonly string[], options: { readonly cwd?: string } = {}): Promise<CommandResult> {
    return await new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        cwd: options.cwd,
        shell: process.platform === 'win32',
        windowsHide: true,
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];

      child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
      child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
      child.on('error', (error) => reject(new IndeterminateDeploymentError('failed to start Wrangler', { cause: error })));
      child.on('close', (code) => {
        resolve({
          exitCode: code ?? 1,
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
        });
      });
    });
  }
}

export function findVersionIdsByTag(value: unknown, tag: string): readonly string[] {
  const matches = new Set<string>();
  visitJson(value, (record) => {
    if (!recordHasTag(record, tag)) return;
    const versionId = readVersionId(record);
    if (versionId !== null) {
      matches.add(versionId);
    }
  });
  return [...matches];
}

export function parseCurrentDeploymentJson(value: unknown): CurrentPublicDeployment {
  const deployment = latestDeployment(value);
  const versions = readArray((deployment as Record<string, unknown>).versions, 'deployment.versions');
  return {
    versions: versions.map((version) => {
      const record = asRecord(version, 'deployment version');
      const providerVersionId = readVersionId(record);
      if (providerVersionId === null) {
        throw new Error('deployment version is missing version_id');
      }
      assertValidProviderVersionId(providerVersionId);

      const percentage = readPercentage(record.percentage);
      return { providerVersionId, percentage };
    }),
  };
}

function latestDeployment(value: unknown): Record<string, unknown> {
  const deployments = Array.isArray(value)
    ? value
    : (() => {
        const record = asRecord(value, 'deployments json');
        return Array.isArray(record.deployments) ? record.deployments : null;
      })();

  if (deployments === null) return asRecord(value, 'deployment');
  if (deployments.length === 0) return { versions: [] };
  if (deployments.length === 1) return asRecord(deployments[0], 'deployment');

  const candidates = deployments.map((entry) => {
    const record = asRecord(entry, 'deployment');
    if (typeof record.created_on !== 'string') {
      throw new Error('multiple deployments require created_on');
    }
    const createdAt = Date.parse(record.created_on);
    if (!Number.isFinite(createdAt)) {
      throw new Error('deployment created_on must be a valid timestamp');
    }
    return { record, createdAt };
  });

  const newest = Math.max(...candidates.map((candidate) => candidate.createdAt));
  const matches = candidates.filter((candidate) => candidate.createdAt === newest);
  if (matches.length !== 1) {
    throw new Error('latest deployment is ambiguous');
  }
  return matches[0]!.record;
}

function recordHasTag(record: Record<string, unknown>, tag: string): boolean {
  if (record.tag === tag || record.correlationTag === tag) return true;
  if (Array.isArray(record.tags) && record.tags.includes(tag)) return true;

  const annotations = record.annotations;
  if (typeof annotations === 'object' && annotations !== null) {
    const annotationsRecord = annotations as Record<string, unknown>;
    if (annotationsRecord['workers/tag'] === tag) return true;
  }

  const metadata = record.metadata;
  if (typeof metadata === 'object' && metadata !== null) {
    const metadataRecord = metadata as Record<string, unknown>;
    if (metadataRecord.tag === tag || metadataRecord.correlationTag === tag) return true;
    if (Array.isArray(metadataRecord.tags) && metadataRecord.tags.includes(tag)) return true;
  }

  return false;
}

function readVersionId(record: Record<string, unknown>): string | null {
  for (const key of ['version_id', 'id', 'versionId']) {
    const value = record[key];
    if (typeof value === 'string' && value.trim() !== '') {
      return value;
    }
  }
  return null;
}

function visitJson(value: unknown, visitor: (record: Record<string, unknown>) => void): void {
  if (Array.isArray(value)) {
    for (const entry of value) visitJson(entry, visitor);
    return;
  }
  if (typeof value !== 'object' || value === null) return;

  const record = value as Record<string, unknown>;
  visitor(record);
  for (const entry of Object.values(record)) {
    visitJson(entry, visitor);
  }
}

function readArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function readPercentage(value: unknown): number {
  const parsed = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  if (!Number.isFinite(parsed)) {
    throw new Error('deployment version percentage must be numeric');
  }
  return parsed;
}

function assertValidProviderVersionId(providerVersionId: string): void {
  if (!VERSION_ID_PATTERN.test(providerVersionId)) {
    throw new Error('providerVersionId must be a non-blank Cloudflare version identifier');
  }
}

function looksIndeterminate(text: string): boolean {
  return /\b(timeout|timed out|econn|network|temporar|unavailable|gateway|5\d\d)\b/i.test(text);
}

function trimDetail(text: string): string {
  const trimmed = text.trim();
  return trimmed.length > 0 ? trimmed.slice(0, 500) : 'Cloudflare activation rejected';
}

function requireNonBlank(value: string, label: string): string {
  if (value.trim() === '') {
    throw new TypeError(`${label} must be a non-blank string`);
  }
  return value;
}
