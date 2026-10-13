/**
 * source-fetch: the ONLY job that holds the read-only private-source deploy
 * key. Trusted control code with zero npm dependencies (git + Node
 * built-ins). It fetches private `main` over SSH with a pinned host key,
 * proves the manifest's exact commit is on main, descends from the previous
 * release and ends at the declared migration ceiling, recomputes the
 * `git archive` SHA-256, and hands the archive on ONLY as ciphertext to the
 * build environment. It never executes, prints or uploads private source,
 * and deletes the key and the repository before it exits.
 *
 * The manifest digest is computed the same way everywhere:
 *   git -c core.autocrlf=false -c core.eol=lf archive --format=tar <commit> | sha256
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { FailClosedError } from '../lib/errors.ts';
import { assertReleaseRun, runContextFrom, setStepOutput, status } from '../lib/github.ts';
import { checkJobEnv, requireEnv } from '../lib/job-env.ts';
import { parseManifest, type ReleaseManifest } from '../lib/manifest.ts';
import { loadRecipientTable, recipientsFor, writeHandoff } from '../lib/recipients.ts';
import { parseTarget } from '../lib/target-config.ts';

/** GitHub's published ed25519 host key (docs: "GitHub's SSH key fingerprints"). */
export const GITHUB_KNOWN_HOSTS = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';
export const SOURCE_REMOTE = 'git@github.com:gaimeore/fine-elements.git';
export const MIGRATIONS_DIR = 'server/migrations';

export interface GitRunner {
  run(args: readonly string[], cwd: string, env: NodeJS.ProcessEnv): Promise<{ readonly code: number; readonly stdout: Buffer }>;
}

export const execGit: GitRunner = {
  run: (args, cwd, env) => new Promise((resolve, reject) => {
    execFile('git', [...args], { cwd, env, encoding: 'buffer', maxBuffer: 1024 * 1024 * 1024, windowsHide: true }, (error, stdout) => {
      if (error && typeof (error as { code?: unknown }).code !== 'number') { reject(new FailClosedError('git could not be started')); return; }
      resolve({ code: error ? (error as { code: number }).code : 0, stdout: stdout as Buffer });
    });
  }),
};

/** The isolated environment git runs with: no user/system config, pinned host key, this key only. */
export function gitEnvironment(dir: string, keyFile: string, knownHostsFile: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH ?? '',
    HOME: dir,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: path.join(dir, 'gitconfig-empty'),
    GIT_TERMINAL_PROMPT: '0',
    GIT_SSH_COMMAND: [
      'ssh', '-F', '/dev/null', '-i', keyFile,
      '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
      '-o', `UserKnownHostsFile=${knownHostsFile}`, '-o', 'GlobalKnownHostsFile=/dev/null',
      '-o', 'BatchMode=yes',
    ].join(' '),
  };
}

/** The newest migration's name without its extension. */
export function migrationCeiling(paths: readonly string[]): string {
  const names = paths
    .map((entry) => entry.split('/').pop() ?? '')
    .filter((name) => /^\d{4}_[a-z0-9_]+\.[a-z]+$/.test(name))
    .map((name) => name.slice(0, name.lastIndexOf('.')))
    .sort();
  const last = names.at(-1);
  if (last === undefined) throw new FailClosedError('the source commit has no migrations');
  return last;
}

export async function fetchAttestedArchive(input: {
  readonly manifest: ReleaseManifest;
  readonly deployKey: string;
  readonly git?: GitRunner;
  readonly remote?: string;
  readonly tempRoot?: string;
}): Promise<Buffer> {
  const git = input.git ?? execGit;
  const dir = mkdtempSync(path.join(input.tempRoot ?? tmpdir(), 'fe-source-'));
  chmodSync(dir, 0o700);
  try {
    const keyFile = path.join(dir, 'deploy_key');
    const knownHosts = path.join(dir, 'known_hosts');
    writeFileSync(keyFile, input.deployKey.endsWith('\n') ? input.deployKey : `${input.deployKey}\n`, { mode: 0o600 });
    writeFileSync(knownHosts, `${GITHUB_KNOWN_HOSTS}\n`, { mode: 0o600 });
    writeFileSync(path.join(dir, 'gitconfig-empty'), '', { mode: 0o600 });
    const env = gitEnvironment(dir, keyFile, knownHosts);
    const repo = path.join(dir, 'repo');
    const must = async (args: readonly string[], cwd: string, failure: string): Promise<Buffer> => {
      const result = await git.run(args, cwd, env);
      if (result.code !== 0) throw new FailClosedError(failure);
      return result.stdout;
    };
    await must(['init', '-q', repo], dir, 'git init failed');
    await must(['fetch', '--no-tags', '-q', input.remote ?? SOURCE_REMOTE, '+refs/heads/main:refs/remotes/origin/main'], repo, 'private main could not be fetched');

    const { source_commit: commit, previous_source_commit: previous } = input.manifest;
    const resolved = (await must(['rev-parse', '--verify', `${commit}^{commit}`], repo, 'source_commit is not reachable from private main')).toString('utf8').trim();
    if (resolved !== commit) throw new FailClosedError('source_commit did not resolve to itself');
    await must(['merge-base', '--is-ancestor', commit, 'refs/remotes/origin/main'], repo, 'source_commit is not reachable from private main');
    if (previous !== null) await must(['merge-base', '--is-ancestor', previous, commit], repo, 'source_commit does not descend from previous_source_commit');

    const migrations = (await must(['ls-tree', '--name-only', commit, `${MIGRATIONS_DIR}/`], repo, 'migration listing failed')).toString('utf8').split('\n').filter(Boolean);
    if (migrationCeiling(migrations) !== input.manifest.migration_ceiling) throw new FailClosedError('the source migration ceiling does not match the manifest');

    const archive = await must(['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar', commit], repo, 'git archive failed');
    if (createHash('sha256').update(archive).digest('hex') !== input.manifest.source_archive_sha256) {
      throw new FailClosedError('source archive SHA-256 does not match the manifest');
    }
    return archive;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export async function main(env: NodeJS.ProcessEnv): Promise<void> {
  checkJobEnv('source-fetch', env);
  const run = runContextFrom(env);
  assertReleaseRun(run);
  const target = parseTarget(env.FE_TARGET);
  const recipients = recipientsFor(loadRecipientTable(), target, ['build']);
  const manifest = parseManifest(JSON.parse(readFileSync(`release/${target}.json`, 'utf8')) as unknown, target);
  const archive = await fetchAttestedArchive({ manifest, deployKey: requireEnv(env, 'SOURCE_DEPLOY_KEY'), tempRoot: env.RUNNER_TEMP });
  const digest = writeHandoff(requireEnv(env, 'FE_HANDOFF_OUT'), archive, recipients, {
    repository: run.repository, workflowRef: run.workflowRef, target, runId: run.runId, runAttempt: run.runAttempt,
    producerJob: 'source-fetch', artifact: 'source',
    bindings: { manifest_sequence: String(manifest.sequence), source_commit: manifest.source_commit },
  });
  setStepOutput(env, 'source_digest', digest);
  status('FE_SOURCE_FETCH=OK');
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.env).catch((error: unknown) => {
    console.error(`FE_SOURCE_FETCH=FAIL ${error instanceof FailClosedError ? error.message : 'failed'}`);
    process.exit(1);
  });
}
