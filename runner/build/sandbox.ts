/**
 * The accepted build sandbox (server/ARCHITECTURE.md §19 "Build security
 * rule"), as exact docker argument vectors. Pure functions: the wrapper
 * executes them, tests and the policy check assert their invariants.
 *
 * Dependency phase: network, but ONLY package.json + package-lock.json are
 * present and lifecycle scripts are off, so no dependency code runs.
 * Build phase: private source + read-only node_modules + snapshot, NO
 * network, no credential, no host socket/home/proc/command files, output
 * only to one bounded directory, stdout/stderr never to the job log.
 */
import { readFileSync } from 'node:fs';

import { FailClosedError } from '../lib/errors.ts';

export const SANDBOX_UID = '10001:10001';

export interface SandboxConfig {
  readonly schema: 'fe-sandbox/1';
  /** node image pinned by digest; null until the RC7 canary accepts one. */
  readonly nodeImage: string | null;
  readonly nodeMajor: number;
}

export function parseSandboxConfig(json: unknown): SandboxConfig {
  const raw = json as Record<string, unknown>;
  if (typeof raw !== 'object' || raw === null || raw.schema !== 'fe-sandbox/1' || Object.keys(raw).sort().join(',') !== 'nodeImage,nodeMajor,schema') {
    throw new FailClosedError('sandbox config is malformed');
  }
  if (raw.nodeImage !== null && (typeof raw.nodeImage !== 'string' || !/^docker\.io\/library\/node@sha256:[0-9a-f]{64}$/.test(raw.nodeImage))) {
    throw new FailClosedError('sandbox node image must be pinned by digest');
  }
  if (!Number.isSafeInteger(raw.nodeMajor) || (raw.nodeMajor as number) < 20) throw new FailClosedError('sandbox node major is malformed');
  return raw as unknown as SandboxConfig;
}

export function loadSandboxConfig(file = 'config/sandbox.json'): SandboxConfig {
  return parseSandboxConfig(JSON.parse(readFileSync(file, 'utf8')) as unknown);
}

export function requireImage(config: SandboxConfig): string {
  if (config.nodeImage === null) throw new FailClosedError('no sandbox image is accepted yet (RC7)');
  return config.nodeImage;
}

const COMMON = [
  '--rm',
  '--user', SANDBOX_UID,
  '--cap-drop', 'ALL',
  '--security-opt', 'no-new-privileges:true',
  '--read-only',
  // PID and UTS namespaces are private by Docker default. docker/cli rejects
  // 'private' for --pid (host|container:) and --uts (host only), so neither
  // flag is ever passed and assertSandboxInvariants refuses any value of them.
  '--ipc', 'private', '--cgroupns', 'private',
  '--ulimit', 'core=0',
  '--log-driver', 'none',
  '--env', 'HOME=/tmp',
] as const;

/** Phase 1: networked, source-less, scripts disabled. */
export function dependencyPhaseArgs(input: { readonly image: string; readonly depsDir: string; readonly name: string }): string[] {
  return [
    'run', '--name', input.name, ...COMMON,
    '--network', 'bridge',
    '--pids-limit', '512', '--memory', '4g', '--memory-swap', '4g', '--cpus', '2',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
    '--mount', `type=bind,src=${input.depsDir},dst=/deps`,
    '--workdir', '/deps',
    input.image,
    'npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/',
  ];
}

/** Phase 2: networkless; the only private code that ever runs. */
export function buildPhaseArgs(input: {
  readonly image: string;
  readonly name: string;
  readonly srcDir: string;
  readonly modulesDir: string;
  readonly snapshotDir: string;
  readonly outDir: string;
  readonly snapshotSha256: string;
  readonly tsxCli: string;
}): string[] {
  if (!/^[0-9a-f]{64}$/.test(input.snapshotSha256)) throw new FailClosedError('snapshot digest is malformed');
  if (!/^dist\/[A-Za-z0-9._/-]+\.m?js$/.test(input.tsxCli)) throw new FailClosedError('tsx entry is malformed');
  const inner = [
    'exec </dev/null >/out/.build.log 2>&1;',
    `exec node /in/node_modules/tsx/${input.tsxCli} /in/src/server/deploy/build-from-inputs.ts`,
    '--src /in/src --modules /in/node_modules --snapshot /in/snapshot/snapshot.json',
    `--snapshot-sha256 ${input.snapshotSha256} --work /work --out /out/dist`,
  ].join(' ');
  return [
    'run', '--name', input.name, ...COMMON,
    '--network', 'none',
    '--pids-limit', '1024', '--memory', '8g', '--memory-swap', '8g', '--cpus', '3',
    '--ulimit', 'nofile=8192',
    '--env', 'NODE_ENV=production', '--env', 'CI=1',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g',
    '--tmpfs', '/work:rw,nosuid,nodev,size=2g',
    '--mount', `type=bind,src=${input.srcDir},dst=/in/src,readonly`,
    '--mount', `type=bind,src=${input.modulesDir},dst=/in/node_modules,readonly`,
    '--mount', `type=bind,src=${input.snapshotDir},dst=/in/snapshot,readonly`,
    '--mount', `type=bind,src=${input.outDir},dst=/out`,
    '--workdir', '/work',
    input.image,
    '/bin/sh', '-c', inner,
  ];
}

/** Exact tokens that may never appear, and fragments that may appear nowhere in any argument. */
const FORBIDDEN_TOKENS = new Set(['-t', '--tty', '-i', '--interactive', '--init', 'host', '--network=host', '--privileged', '--cap-add', '--env-file', '--volume', '-v']);
const FORBIDDEN_FRAGMENTS = ['docker.sock', 'containerd', 'GITHUB_', 'ACTIONS_', 'RUNNER_', '/var/run', '/proc'];
/** Namespace-sharing flags in any form, and joined '--flag=value' forms of the pinned security flags (which would dodge the sequence checks). */
const FORBIDDEN_FLAG = /^--(pid|uts|userns)(=|$)|^--(network|net|ipc|cgroupns|user|cap-drop|cap-add|security-opt|log-driver|mount|env|ulimit|read-only)=/;
/** Every bind source lives under the wrapper-owned root, never a runner or home directory. */
export const SANDBOX_ROOT = '/fe/';

/** The invariants every generated vector must hold (tests + policy). */
export function assertSandboxInvariants(args: readonly string[], phase: 'dependency' | 'build'): void {
  const has = (...sequence: string[]): boolean => args.some((_, i) => sequence.every((s, j) => args[i + j] === s));
  for (const required of [
    ['--user', SANDBOX_UID], ['--cap-drop', 'ALL'], ['--security-opt', 'no-new-privileges:true'], ['--read-only'],
    ['--ipc', 'private'], ['--cgroupns', 'private'],
    ['--ulimit', 'core=0'], ['--log-driver', 'none'], ['--rm'],
  ]) {
    if (!has(...required)) throw new FailClosedError(`sandbox is missing ${required.join(' ')}`);
  }
  if (!args.includes('--pids-limit') || !args.includes('--memory') || !args.includes('--cpus')) throw new FailClosedError('sandbox has no resource limits');
  if (phase === 'build' && !has('--network', 'none')) throw new FailClosedError('the build sandbox must have no network');
  if (phase === 'dependency' && !args.includes('--ignore-scripts')) throw new FailClosedError('dependency install must disable lifecycle scripts');
  for (const arg of args) {
    if (FORBIDDEN_TOKENS.has(arg) || FORBIDDEN_FLAG.test(arg) || FORBIDDEN_FRAGMENTS.some((fragment) => arg.includes(fragment))) {
      throw new FailClosedError('sandbox vector contains a forbidden element');
    }
  }
  const envs = args.flatMap((arg, i) => (args[i - 1] === '--env' ? [arg] : []));
  for (const env of envs) {
    if (!['HOME=/tmp', 'NODE_ENV=production', 'CI=1'].includes(env)) throw new FailClosedError('sandbox environment is not the fixed allowlist');
  }
  for (const mount of args.flatMap((arg, i) => (args[i - 1] === '--mount' ? [arg] : []))) {
    if (!mount.startsWith('type=bind,')) throw new FailClosedError('sandbox mounts must be explicit binds');
    const src = /src=([^,]+)/.exec(mount)?.[1] ?? '';
    if (!src.startsWith(SANDBOX_ROOT) || src.includes('..')) throw new FailClosedError('sandbox bind sources must live under /fe/');
    const dst = /dst=([^,]+)/.exec(mount)?.[1];
    if (phase === 'build' && dst !== '/out' && !mount.endsWith(',readonly')) throw new FailClosedError('only /out may be writable');
  }
}
