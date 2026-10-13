/**
 * source-fetch against a SYNTHETIC local repository (no network, no Fine
 * Elements source): reachability from main, ancestry, migration ceiling,
 * archive digest, key/known-hosts material and cleanup.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';

import { parseManifest, type ReleaseManifest } from '../runner/lib/manifest.ts';
import { GITHUB_KNOWN_HOSTS, fetchAttestedArchive, gitEnvironment, migrationCeiling } from '../runner/source/source-fetch.ts';

let root = '';
let remote = '';
const commits: string[] = [];
let sideCommit = '';

const git = (cwd: string, ...args: string[]): string => execFileSync('git', args, {
  cwd, encoding: 'utf8',
  env: { ...process.env, GIT_AUTHOR_NAME: 'canary', GIT_AUTHOR_EMAIL: 'canary@example.invalid', GIT_COMMITTER_NAME: 'canary', GIT_COMMITTER_EMAIL: 'canary@example.invalid', GIT_CONFIG_NOSYSTEM: '1' },
}).trim();

const archiveSha = (commit: string): string => createHash('sha256')
  .update(execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', '--format=tar', commit], { cwd: remote }))
  .digest('hex');

before(() => {
  root = mkdtempSync(path.join(tmpdir(), 'fe-source-fixture-'));
  remote = path.join(root, 'canary');
  mkdirSync(path.join(remote, 'server', 'migrations'), { recursive: true });
  git(root, 'init', '-q', '-b', 'main', remote);
  git(remote, 'config', 'core.autocrlf', 'false');
  for (const [index, migration] of ['0001_first.sql', '0002_second.sql', '0003_third.sql'].entries()) {
    writeFileSync(path.join(remote, 'server', 'migrations', migration), `-- synthetic ${index}\n`);
    writeFileSync(path.join(remote, 'README.md'), `canary ${index}\n`);
    git(remote, 'add', '-A');
    git(remote, 'commit', '-q', '-m', `canary ${index}`);
    commits.push(git(remote, 'rev-parse', 'HEAD'));
  }
  git(remote, 'checkout', '-q', '-b', 'side');
  writeFileSync(path.join(remote, 'side.txt'), 'not on main\n');
  git(remote, 'add', '-A');
  git(remote, 'commit', '-q', '-m', 'side');
  sideCommit = git(remote, 'rev-parse', 'HEAD');
  git(remote, 'checkout', '-q', 'main');
});

after(() => { rmSync(root, { recursive: true, force: true }); });

function manifestFor(commit: string, previous: string | null, ceiling: string, archive = archiveSha(commit)): ReleaseManifest {
  return parseManifest({
    schema: 'fine-elements-release-manifest/1', target: 'test', sequence: previous === null ? 1 : 2,
    source_repository: 'gaimeore/fine-elements', source_commit: commit, source_archive_sha256: archive,
    previous_source_commit: previous, migration_ceiling: ceiling,
  });
}

describe('source-fetch attestation (synthetic repository)', () => {
  test('the exact main commit is fetched and its archive digest proven', async () => {
    const tempRoot = mkdtempSync(path.join(root, 'tmp-'));
    const archive = await fetchAttestedArchive({ manifest: manifestFor(commits[2]!, commits[1]!, '0003_third'), deployKey: 'synthetic-not-a-key', remote, tempRoot });
    assert.equal(createHash('sha256').update(archive).digest('hex'), archiveSha(commits[2]!));
    assert.deepEqual(readdirSync(tempRoot), [], 'key, known_hosts and repository are deleted');
  });

  test('a commit that is not reachable from main fails closed', async () => {
    await assert.rejects(fetchAttestedArchive({ manifest: manifestFor(sideCommit, commits[2]!, '0003_third'), deployKey: 'k', remote, tempRoot: root }), /not reachable from private main/);
  });

  test('a commit that does not descend from the previous release fails closed', async () => {
    await assert.rejects(fetchAttestedArchive({ manifest: manifestFor(commits[1]!, commits[2]!, '0002_second'), deployKey: 'k', remote, tempRoot: root }), /does not descend/);
  });

  test('a migration ceiling mismatch fails closed', async () => {
    await assert.rejects(fetchAttestedArchive({ manifest: manifestFor(commits[2]!, commits[1]!, '0002_second'), deployKey: 'k', remote, tempRoot: root }), /migration ceiling/);
  });

  test('an archive digest mismatch fails closed', async () => {
    await assert.rejects(fetchAttestedArchive({ manifest: manifestFor(commits[2]!, commits[1]!, '0003_third', 'f'.repeat(64)), deployKey: 'k', remote, tempRoot: root }), /archive SHA-256/);
  });

  test('git runs isolated: pinned host key, strict checking, this identity only, no user or system config', () => {
    const env = gitEnvironment('/x', '/x/deploy_key', '/x/known_hosts');
    assert.match(env.GIT_SSH_COMMAND!, /-o StrictHostKeyChecking=yes/);
    assert.match(env.GIT_SSH_COMMAND!, /-o IdentitiesOnly=yes/);
    assert.match(env.GIT_SSH_COMMAND!, /-o UserKnownHostsFile=\/x\/known_hosts/);
    assert.match(env.GIT_SSH_COMMAND!, /-o GlobalKnownHostsFile=\/dev\/null/);
    assert.equal(env.GIT_CONFIG_NOSYSTEM, '1');
    assert.equal(env.HOME, '/x');
    assert.equal(GITHUB_KNOWN_HOSTS, 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl');
    assert.ok(!Object.keys(env).some((name) => /TOKEN|DATABASE|B2_|R2_/.test(name)));
  });

  test('the migration ceiling is the newest migration name', () => {
    assert.equal(migrationCeiling(['server/migrations/0001_a.sql', 'server/migrations/0011_live_catalogue_control.sql', 'server/migrations/README.md']), '0011_live_catalogue_control');
    assert.throws(() => migrationCeiling(['server/migrations/README.md']), /no migrations/);
  });

  test('source-fetch has zero npm dependencies and never executes fetched files', () => {
    assert.ok(existsSync('runner/source/source-fetch.ts'));
    const text = execFileSync('git', ['grep', '-h', '^import', '--', 'runner/source/source-fetch.ts'], { encoding: 'utf8' }).trim().split('\n');
    for (const line of text) assert.match(line, /from '(node:[a-z_/]+|\.\.\/lib\/[a-z-]+\.ts)'/, line);
  });
});
