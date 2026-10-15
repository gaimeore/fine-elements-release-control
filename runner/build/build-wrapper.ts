/**
 * build: the trusted HOST wrapper of the accepted R2 sandbox build. It holds
 * only its own handoff key. Private source is extracted from the verified
 * archive as data, dependencies are installed with the source absent, and
 * private code runs ONLY inside the networkless sandbox (./sandbox.ts).
 * Every docker invocation writes to host-owned log files, never to the job
 * log; this wrapper prints one fixed status line. The bundle leaves only as
 * ciphertext to the deploy recipient, the file manifest only to the verify
 * recipient, and the build log only to the offline audit recipient.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { FailClosedError } from '../lib/errors.ts';
import { assertReleaseRun, runContextFrom, setStepOutput, status, type RunContext } from '../lib/github.ts';
import type { HandoffContext } from '../lib/handoff.ts';
import { checkJobEnv, requireEnv } from '../lib/job-env.ts';
import { parseManifest, type ReleaseManifest } from '../lib/manifest.ts';
import { loadRecipientTable, readHandoff, recipientsFor, writeHandoff } from '../lib/recipients.ts';
import { readTar } from '../lib/tar.ts';
import { parseTarget, type Target } from '../lib/target-config.ts';
import { packBundle, validateBundleTree, type BundleFile } from '../deploy/bundle.ts';
import { assertSandboxInvariants, buildPhaseArgs, dependencyPhaseArgs, loadSandboxConfig, requireImage, type SandboxConfig } from './sandbox.ts';

export interface BuildInput {
  readonly snapshot: Buffer;
  readonly snapshotSha256: string;
  readonly sourceCommit: string;
  readonly manifestSequence: number;
}

export function parseBuildInput(json: unknown, manifest: ReleaseManifest): BuildInput {
  const raw = json as Record<string, unknown>;
  if (typeof raw !== 'object' || raw === null || raw.schema !== 'fe-build-input/1') throw new FailClosedError('build input is malformed');
  if (raw.source_commit !== manifest.source_commit || raw.manifest_sequence !== manifest.sequence) throw new FailClosedError('build input is not bound to this manifest');
  if (typeof raw.snapshot_b64 !== 'string' || typeof raw.snapshot_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(raw.snapshot_sha256)) throw new FailClosedError('build input is malformed');
  const snapshot = Buffer.from(raw.snapshot_b64, 'base64');
  if (createHash('sha256').update(snapshot).digest('hex') !== raw.snapshot_sha256) throw new FailClosedError('build input snapshot digest mismatch');
  return { snapshot, snapshotSha256: raw.snapshot_sha256, sourceCommit: manifest.source_commit, manifestSequence: manifest.sequence };
}

/** Extracts the verified archive as plain data (no links, no modes from the archive). */
export function extractSource(archive: Buffer, destination: string): void {
  for (const entry of readTar(archive)) {
    const target = path.join(destination, ...entry.path.split('/'));
    if (entry.type === 'dir') { mkdirSync(target, { recursive: true, mode: 0o755 }); continue; }
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
    writeFileSync(target, entry.data, { flag: 'wx', mode: 0o644 });
  }
}

/**
 * The ONE reviewed exception to exact-major equality (RC9 P1-scoped): TEST
 * release source 1e1e418 pins Node 20.11.0 with engines ">=20.11.0" and may
 * be built only for target test on the accepted Node 22 image. Every field
 * must match exactly; any other target (or none), source, archive, .nvmrc,
 * engines or image stays exact.
 */
export const NODE_MAJOR_EXCEPTION = {
  target: 'test',
  sourceCommit: '1e1e418e4a638f29519650995f25049b1cfc2d37',
  sourceArchiveSha256: '2f9ffc0cbd0efafdf84f80fb10d37d57233d6ef50b33a9f7622ee30a3f1755ad',
  nvmrc: '20.11.0\n',
  enginesNode: '>=20.11.0',
  nodeImage: 'docker.io/library/node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392',
  nodeMajor: 22,
} as const;

/** The verified source archive being built: its manifest commit, the SHA-256 of its exact bytes and the run's target (absent: no exception). */
export interface SourceIdentity {
  readonly sourceCommit: string;
  readonly archiveSha256: string;
  readonly target?: Target;
}

/** The source's pinned Node major must equal the sandbox image's, except for NODE_MAJOR_EXCEPTION. */
export function assertNodeMajor(srcDir: string, config: SandboxConfig, source: SourceIdentity): void {
  const file = path.join(srcDir, '.nvmrc');
  if (!existsSync(file)) throw new FailClosedError('source has no .nvmrc');
  const nvmrc = readFileSync(file, 'utf8');
  const major = /^v?(\d+)/.exec(nvmrc.trim())?.[1];
  if (Number(major) === config.nodeMajor) return;
  if (isNodeMajorException(srcDir, nvmrc, config, source)) return;
  throw new FailClosedError('source Node major does not match the sandbox image');
}

function isNodeMajorException(srcDir: string, nvmrc: string, config: SandboxConfig, source: SourceIdentity): boolean {
  const exception = NODE_MAJOR_EXCEPTION;
  if (source.target !== exception.target) return false;
  if (source.sourceCommit !== exception.sourceCommit || source.archiveSha256 !== exception.sourceArchiveSha256) return false;
  if (nvmrc !== exception.nvmrc || config.nodeImage !== exception.nodeImage || config.nodeMajor !== exception.nodeMajor) return false;
  try {
    const pkg = JSON.parse(readFileSync(path.join(srcDir, 'package.json'), 'utf8')) as { engines?: { node?: unknown } } | null;
    return pkg?.engines?.node === exception.enginesNode;
  } catch {
    return false;
  }
}

/** Only package.json + package-lock.json reach the dependency phase; an .npmrc fails closed. */
export function prepareDependencyInputs(srcDir: string, depsDir: string): void {
  if (existsSync(path.join(srcDir, '.npmrc'))) throw new FailClosedError('source .npmrc is not accepted');
  mkdirSync(depsDir, { recursive: true });
  for (const name of ['package.json', 'package-lock.json']) {
    if (!existsSync(path.join(srcDir, name))) throw new FailClosedError(`source has no ${name}`);
    writeFileSync(path.join(depsDir, name), readFileSync(path.join(srcDir, name)), { mode: 0o644 });
  }
}

/** tsx's CLI entry from its own package.json (data, never executed on the host). */
export function tsxCliEntry(modulesDir: string): string {
  const pkg = JSON.parse(readFileSync(path.join(modulesDir, 'tsx', 'package.json'), 'utf8')) as { bin?: unknown };
  const bin = typeof pkg.bin === 'string' ? pkg.bin : (pkg.bin as Record<string, unknown> | undefined)?.tsx;
  if (typeof bin !== 'string') throw new FailClosedError('tsx entry not found');
  return bin.replace(/^\.\//, '');
}

export interface HostCommand {
  /** Runs a host command with stdio to a host-owned log file only. Returns the exit code. */
  run(command: string, args: readonly string[], logFile: string): Promise<number>;
}

export const hostCommand: HostCommand = {
  run: (command, args, logFile) => new Promise((resolve) => {
    const fd = openSync(logFile, 'a', 0o600);
    const child = spawn(command, [...args], { stdio: ['ignore', fd, fd], windowsHide: true });
    child.on('error', () => { closeSync(fd); resolve(127); });
    child.on('close', (code) => { closeSync(fd); resolve(code ?? 1); });
  }),
};

export interface SandboxBuildResult {
  readonly bundle: Buffer;
  readonly files: readonly BundleFile[];
  readonly log: Buffer;
}

/** The full host sequence. RC2 never calls it with Fine Elements source; RC7 proves it on a canary first. */
export async function runSandboxBuild(input: {
  readonly archive: Buffer;
  readonly build: BuildInput;
  readonly config: SandboxConfig;
  /** The trusted FE_TARGET of this run; only needed for NODE_MAJOR_EXCEPTION. */
  readonly target?: Target;
  readonly host?: HostCommand;
  readonly root?: string;
}): Promise<SandboxBuildResult> {
  const host = input.host ?? hostCommand;
  const root = input.root ?? '/fe';
  const image = requireImage(input.config);
  const dirs = { src: `${root}/src`, deps: `${root}/deps`, snapshot: `${root}/snapshot`, out: `${root}/out`, log: `${root}/log` };
  const must = async (command: string, args: readonly string[], failure: string): Promise<void> => {
    if (await host.run(command, args, `${dirs.log}/host.log`) !== 0) throw new FailClosedError(failure);
  };
  try {
    // The log directory lives under the root, so creating the root cannot log into it.
    if (await host.run('sudo', ['install', '-d', '-m', '0755', '-o', String(process.getuid?.() ?? 0), root], '/dev/null') !== 0) {
      throw new FailClosedError('sandbox root could not be created');
    }
    mkdirSync(dirs.log, { recursive: true, mode: 0o700 });
    extractSource(input.archive, dirs.src);
    // The identity is recomputed from the exact bytes extracted, never taken from a caller.
    assertNodeMajor(dirs.src, input.config, { sourceCommit: input.build.sourceCommit, archiveSha256: createHash('sha256').update(input.archive).digest('hex'), target: input.target });
    prepareDependencyInputs(dirs.src, dirs.deps);
    await must('sudo', ['chown', '-R', '10001:10001', dirs.deps], 'dependency directory could not be prepared');

    const depsArgs = dependencyPhaseArgs({ image, depsDir: dirs.deps, name: 'fe-deps' });
    assertSandboxInvariants(depsArgs, 'dependency');
    if (await host.run('docker', depsArgs, `${dirs.log}/deps.log`) !== 0) throw new FailClosedError('dependency phase failed');
    await host.run('docker', ['rm', '-f', 'fe-deps'], `${dirs.log}/host.log`);

    mkdirSync(dirs.snapshot, { recursive: true, mode: 0o755 });
    writeFileSync(`${dirs.snapshot}/snapshot.json`, input.build.snapshot, { mode: 0o644 });
    await must('sudo', ['fallocate', '-l', '768M', `${root}/out.img`], 'output image could not be allocated');
    await must('sudo', ['mkfs.ext4', '-q', '-N', '30000', `${root}/out.img`], 'output filesystem could not be created');
    await must('sudo', ['mkdir', '-p', dirs.out], 'output mount point could not be created');
    await must('sudo', ['mount', '-o', 'loop,nosuid,nodev,noexec', `${root}/out.img`, dirs.out], 'output filesystem could not be mounted');
    await must('sudo', ['chown', '10001:10001', dirs.out], 'output filesystem could not be prepared');

    const buildArgs = buildPhaseArgs({
      image, name: 'fe-build', srcDir: dirs.src, modulesDir: `${dirs.deps}/node_modules`, snapshotDir: dirs.snapshot,
      outDir: dirs.out, snapshotSha256: input.build.snapshotSha256, tsxCli: tsxCliEntry(`${dirs.deps}/node_modules`),
    });
    assertSandboxInvariants(buildArgs, 'build');
    const code = await host.run('timeout', ['--kill-after=15s', '1200', 'docker', ...buildArgs], `${dirs.log}/docker-client.log`);
    await host.run('docker', ['rm', '-f', 'fe-build'], `${dirs.log}/host.log`);
    const log = Buffer.concat([dirs.out + '/.build.log', `${dirs.log}/deps.log`, `${dirs.log}/docker-client.log`]
      .filter((file) => existsSync(file)).map((file) => readFileSync(file)));
    if (code !== 0) throw Object.assign(new FailClosedError('sandbox build failed'), { log });
    const files = validateBundleTree(`${dirs.out}/dist`, 'forbidden');
    return { bundle: packBundle(`${dirs.out}/dist`, files), files, log };
  } finally {
    await host.run('sudo', ['umount', dirs.out], `${dirs.log}/host.log`).catch(() => 1);
    await host.run('sudo', ['rm', '-rf', root], '/dev/null').catch(() => 1);
  }
}

export function buildContext(run: RunContext, target: Target, manifest: ReleaseManifest, producerJob: string, artifact: string): HandoffContext {
  return {
    repository: run.repository, workflowRef: run.workflowRef, target, runId: run.runId, runAttempt: run.runAttempt, producerJob, artifact,
    bindings: { manifest_sequence: String(manifest.sequence), source_commit: manifest.source_commit },
  };
}

export async function main(env: NodeJS.ProcessEnv): Promise<void> {
  checkJobEnv('build', env);
  const run = runContextFrom(env);
  assertReleaseRun(run);
  const target = parseTarget(env.FE_TARGET);
  const config = loadSandboxConfig();
  const recipients = loadRecipientTable();
  const manifest = parseManifest(JSON.parse(readFileSync(`release/${target}.json`, 'utf8')) as unknown, target);
  const key = requireEnv(env, 'FE_HANDOFF_PRIVATE_KEY');
  const archive = readHandoff('handoff/source.fehandoff', env.SOURCE_DIGEST, key, buildContext(run, target, manifest, 'source-fetch', 'source'));
  if (createHash('sha256').update(archive).digest('hex') !== manifest.source_archive_sha256) throw new FailClosedError('source archive SHA-256 does not match the manifest');
  const build = parseBuildInput(JSON.parse(readHandoff('handoff/build-input.fehandoff', env.BUILD_INPUT_DIGEST, key,
    buildContext(run, target, manifest, 'select-claim-prepare', 'build-input')).toString('utf8')) as unknown, manifest);

  let result: SandboxBuildResult;
  try {
    result = await runSandboxBuild({ archive, build, config, target });
  } catch (error) {
    const log = (error as { log?: Buffer }).log;
    if (log !== undefined) writeHandoff('handoff/build-log.fehandoff', log, recipientsFor(recipients, target, ['audit']), buildContext(run, target, manifest, 'build', 'build-log'));
    throw error;
  }
  const metadata = {
    schema: 'fe-bundle-metadata/1',
    source_commit: manifest.source_commit,
    source_archive_sha256: manifest.source_archive_sha256,
    migration_ceiling: manifest.migration_ceiling,
    manifest_sequence: manifest.sequence,
    snapshot_sha256: build.snapshotSha256,
    bundle_sha256: createHash('sha256').update(result.bundle).digest('hex'),
    bundle_bytes: result.bundle.length,
    image: config.nodeImage,
  };
  const bundleDigest = writeHandoff('handoff/bundle.fehandoff', Buffer.from(JSON.stringify({ metadata, bundle_b64: result.bundle.toString('base64') }), 'utf8'),
    recipientsFor(recipients, target, ['deploy']), buildContext(run, target, manifest, 'build', 'bundle'));
  const filesDigest = writeHandoff('handoff/bundle-files.fehandoff', Buffer.from(JSON.stringify({ metadata, files: result.files }), 'utf8'),
    recipientsFor(recipients, target, ['verify']), buildContext(run, target, manifest, 'build', 'bundle-files'));
  writeHandoff('handoff/build-log.fehandoff', result.log, recipientsFor(recipients, target, ['audit']), buildContext(run, target, manifest, 'build', 'build-log'));
  setStepOutput(env, 'bundle_digest', bundleDigest);
  setStepOutput(env, 'bundle_files_digest', filesDigest);
  status('FE_BUILD_SANDBOX=OK');
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.env).catch((error: unknown) => {
    console.error(`FE_BUILD_SANDBOX=FAIL ${error instanceof FailClosedError ? error.message : 'failed'}`);
    process.exit(1);
  });
}
