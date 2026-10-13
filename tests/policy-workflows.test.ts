/**
 * Workflow shape (the D2 guarantees removed from the private repository at
 * RC1P, re-established here), the trusted policy engine, the content
 * scanner, and the App JWT. Forbidden samples are assembled at runtime so
 * this file itself stays clean under the content scan.
 */
import assert from 'node:assert/strict';
import { createVerify, generateKeyPairSync } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import { parse } from 'yaml';

import { JOB_ENV } from '../runner/lib/job-env.ts';
import { appJwt, summarize } from '../runner/policy/policy-cli.ts';
import { ENVIRONMENT_SECRETS, evaluateFiles, evaluatePullRequest, lintWorkflow, parseActionAllowlist, scanContent, type ActionAllowlist } from '../runner/policy/policy-engine.ts';
import type { ReleaseManifest } from '../runner/lib/manifest.ts';

type Rec = Record<string, unknown>;
const ACTIONS: ActionAllowlist = parseActionAllowlist(JSON.parse(readFileSync('config/actions.json', 'utf8')));
const WF = (name: string): string => readFileSync(`.github/workflows/${name}`, 'utf8');
const jobs = (name: string): Record<string, Rec> => (parse(WF(name)) as { jobs: Record<string, Rec> }).jobs;
const stepEnv = (job: Rec): Record<string, string> => Object.assign({}, ...((job.steps as Rec[]).filter((s) => s.env !== undefined).map((s) => s.env as Record<string, string>)));
const secretNames = (job: Rec): string[] => [...JSON.stringify(job).matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]!).sort();

describe('workflow shape — backup (ported D2 guarantees)', () => {
  for (const t of ['test', 'prod'] as const) {
    const T = t.toUpperCase();
    const backup = jobs(`backup-${t}.yml`);

    test(`${t}: exactly verify-scan → write-missing → verify-again, each in its own Environment`, () => {
      assert.deepEqual(Object.keys(backup), ['verify-scan', 'write-missing', 'verify-again']);
      assert.equal(backup['verify-scan']!.environment, `${t}-backup-verify`);
      assert.equal(backup['write-missing']!.environment, `${t}-backup-write`);
      assert.equal(backup['write-missing']!.needs, 'verify-scan');
      assert.equal(backup['verify-again']!.environment, `${t}-backup-verify`);
      assert.deepEqual(backup['verify-again']!.needs, ['verify-scan', 'write-missing']);
    });

    test(`${t}: verify jobs hold restore reader + verifier DB only; the writer holds R2 read + B2 writer only`, () => {
      assert.deepEqual(secretNames(backup['verify-scan']!), [`B2_${T}_RESTORE_APPLICATION_KEY`, `B2_${T}_RESTORE_KEY_ID`, `${T}_BACKUP_VERIFIER_DATABASE_URL`, 'TARGET_CONFIG_JSON'].sort());
      assert.deepEqual(secretNames(backup['verify-again']!), [`B2_${T}_RESTORE_APPLICATION_KEY`, `B2_${T}_RESTORE_KEY_ID`, `${T}_BACKUP_VERIFIER_DATABASE_URL`, `${T}_BACKUP_VERIFY_HANDOFF_KEY`, 'TARGET_CONFIG_JSON'].sort());
      assert.deepEqual(secretNames(backup['write-missing']!), [`B2_${T}_WRITER_APPLICATION_KEY`, `B2_${T}_WRITER_KEY_ID`, `R2_${T}_SOURCE_ACCESS_KEY_ID`, `R2_${T}_SOURCE_SECRET_ACCESS_KEY`, `${T}_BACKUP_WRITE_HANDOFF_KEY`, 'TARGET_CONFIG_JSON'].sort());
    });

    test(`${t}: each job passes exactly the env its CLI mode requires, and none it forbids`, () => {
      const modeOf = { 'verify-scan': 'backup-scan', 'write-missing': 'backup-write', 'verify-again': 'backup-verify' } as const;
      for (const [job, kind] of Object.entries(modeOf)) {
        const env = stepEnv(backup[job]!);
        const credentialNames = Object.keys(env).filter((n) => !/^(FE_TARGET|SCAN_DIGEST|WRITE_DIGEST|GH_TOKEN)$/.test(n)).sort();
        assert.deepEqual(credentialNames, [...JOB_ENV[kind]].sort(), job);
        assert.match(JSON.stringify(backup[job]), new RegExp(`backup-cli\\.ts ${kind.replace('backup-', '')} --target ${t}`), job);
      }
    });

    test(`${t}: no deploy credential, no other-target secret, read-only token and production-release only`, () => {
      const text = WF(`backup-${t}.yml`);
      assert.doesNotMatch(text, /CLOUDFLARE_|DEPLOY_RUNNER|SOURCE_DEPLOY_KEY/);
      assert.doesNotMatch(text, new RegExp(t === 'test' ? 'PROD_|_PROD' : 'TEST_|_TEST'));
      assert.match(text, /^permissions: \{\}$/m);
      for (const job of Object.values(backup)) {
        assert.deepEqual(job.permissions, { contents: 'read' });
        assert.equal((job.steps as Rec[])[0]!.run, 'test "$GITHUB_REF" = "refs/heads/production-release"');
        assert.match(JSON.stringify(job), /assert-release-tip\.ts/);
        assert.match(JSON.stringify(job), /persist-credentials":false/);
      }
    });
  }

  test('the scheduler is secretless: Actions write only, no checkout, dispatches the backup workflows on production-release, inert until enabled', () => {
    const scheduler = WF('scheduler.yml');
    assert.doesNotMatch(scheduler.replace(/^#.*$/gm, ''), /secrets\.|environment:|actions\/checkout|workflow_dispatch|inputs|-f /);
    assert.match(scheduler, /^permissions: \{\}$/m);
    const s = jobs('scheduler.yml');
    for (const [name, t] of [['wake-test', 'TEST'], ['wake-prod', 'PROD']] as const) {
      assert.deepEqual(s[name]!.permissions, { actions: 'write' });
      assert.equal(s[name]!.if, `vars.FE_BACKUP_SCHEDULER_${t}_ENABLED == 'true'`);
      assert.match(JSON.stringify(s[name]), new RegExp(`gh workflow run backup-${t.toLowerCase()}\\.yml --repo \\\\"\\$GITHUB_REPOSITORY\\\\" --ref production-release`));
    }
  });
});

describe('workflow shape — deploy', () => {
  for (const t of ['test', 'prod'] as const) {
    const T = t.toUpperCase();
    const d = jobs(`deploy-${t}.yml`);
    test(`${t}: select → source-fetch → build → deploy → verify, one credential family each`, () => {
      assert.deepEqual(Object.keys(d), ['select-claim-prepare', 'source-fetch', 'build', 'deploy', 'verify']);
      assert.deepEqual(secretNames(d['select-claim-prepare']!), [`${T}_DEPLOY_RUNNER_DATABASE_URL`, `R2_${T}_DEPLOY_READER_ACCESS_KEY_ID`, `R2_${T}_DEPLOY_READER_SECRET_ACCESS_KEY`, 'TARGET_CONFIG_JSON'].sort());
      assert.deepEqual(secretNames(d['source-fetch']!), [`${T}_SOURCE_DEPLOY_KEY`]);
      assert.deepEqual(secretNames(d.build!), [`${T}_BUILD_HANDOFF_KEY`]);
      assert.deepEqual(secretNames(d.deploy!), [`CLOUDFLARE_${T}_PUBLIC_DEPLOY_TOKEN`, `${T}_DEPLOY_HANDOFF_KEY`, `${T}_DEPLOY_RUNNER_DATABASE_URL`, 'TARGET_CONFIG_JSON'].sort());
      assert.deepEqual(secretNames(d.verify!), [`CLOUDFLARE_${T}_PUBLIC_READ_TOKEN`, `${T}_DEPLOY_RUNNER_DATABASE_URL`, `${T}_VERIFY_HANDOFF_KEY`, 'TARGET_CONFIG_JSON'].sort());
      for (const [name, job] of Object.entries(d)) assert.equal(job.environment, `${t}-${name === 'select-claim-prepare' ? 'deploy-prepare' : name}`);
    });

    test(`${t}: the deploy key never reaches a job that runs private code; source-fetch and build install no npm dependencies`, () => {
      const others = ['select-claim-prepare', 'build', 'deploy', 'verify'].map((n) => JSON.stringify(d[n]));
      for (const text of others) assert.doesNotMatch(text, /SOURCE_DEPLOY_KEY/);
      for (const name of ['source-fetch', 'build']) assert.doesNotMatch(JSON.stringify(d[name]), /npm ci/);
      assert.match(JSON.stringify(d.build), /runner\/build\/build-wrapper\.ts/);
    });

    test(`${t}: a parameterless wake-up, serialized per target, never cancelled`, () => {
      const doc = parse(WF(`deploy-${t}.yml`)) as Rec;
      assert.deepEqual(doc.on, { workflow_dispatch: null });
      assert.deepEqual(doc.concurrency, { group: `fe-deploy-${t}`, 'cancel-in-progress': false });
    });
  }

  test('only policy.yml references the control-policy environment, and it never checks out the PR', () => {
    for (const name of readdirSync('.github/workflows')) {
      if (name !== 'policy.yml') assert.doesNotMatch(WF(name), /control-policy/, name);
    }
    const policy = WF('policy.yml');
    assert.match(policy, /environment: control-policy/);
    assert.doesNotMatch(policy, /pull_request\.head|ref:/);
  });
});

function mutate(name: string, from: string | RegExp, to: string): string {
  const text = WF(name);
  const next = text.replace(from, to);
  assert.notEqual(next, text, `mutation did not apply: ${String(from)}`);
  return next;
}
const rules = (file: string, text: string): string[] => lintWorkflow(`.github/workflows/${file}`, text, ACTIONS).map((f) => f.rule);

describe('policy engine — workflow rules', () => {
  test('every committed workflow and the whole tree pass', () => {
    for (const name of readdirSync('.github/workflows')) assert.deepEqual(rules(name, WF(name)), [], name);
  });

  test('each weakening is caught', () => {
    const cases: [string, string, string | RegExp, string][] = [
      ['trigger-allowlist', 'backup-test.yml', 'workflow_dispatch:', 'workflow_run:'],
      ['trigger-allowlist', 'control-ci.yml', 'pull_request:', 'pull_request_target:'],
      ['dispatch-inputs', 'deploy-test.yml', 'workflow_dispatch:', 'workflow_dispatch:\n    inputs:\n      ref:\n        type: string'],
      ['permissions', 'backup-test.yml', 'permissions: {}', 'permissions: write-all'],
      ['permissions', 'deploy-test.yml', '    permissions:\n      contents: read\n    outputs:\n      mode', '    permissions:\n      contents: write\n    outputs:\n      mode'],
      ['action-pin', 'backup-test.yml', /actions\/checkout@[0-9a-f]{40}/, 'actions/checkout@v4'],
      ['action-pin', 'control-ci.yml', /actions\/setup-node@[0-9a-f]{40}/, 'some-org/setup-node@0123456789012345678901234567890123456789'],
      ['checkout', 'backup-test.yml', 'persist-credentials: false', 'persist-credentials: true'],
      ['cache', 'control-ci.yml', 'node-version: 22', "node-version: 22\n          cache: npm"],
      ['credential-family', 'backup-test.yml', 'secrets.B2_TEST_RESTORE_KEY_ID', 'secrets.B2_TEST_WRITER_KEY_ID'],
      ['credential-family', 'deploy-test.yml', 'secrets.TEST_BUILD_HANDOFF_KEY', 'secrets.TEST_SOURCE_DEPLOY_KEY'],
      ['secrets', 'control-ci.yml', 'run: npm test', "run: npm test\n        env:\n          X: ${{ secrets.TARGET_CONFIG_JSON }}"],
      ['release-assertion', 'backup-test.yml', 'test "$GITHUB_REF" = "refs/heads/production-release"', 'true'],
      ['control-policy', 'backup-test.yml', 'environment: test-backup-write', 'environment: control-policy'],
      ['environment', 'backup-test.yml', 'environment: test-backup-write', 'environment: production'],
      ['shell-interpolation', 'backup-test.yml', '--target test --out handoff/backup-scan.fehandoff', '--target ${{ github.event.inputs.x }} --out handoff/backup-scan.fehandoff'],
      ['concurrency', 'backup-test.yml', 'cancel-in-progress: false', 'cancel-in-progress: true'],
      ['scheduler', 'scheduler.yml', "vars.FE_BACKUP_SCHEDULER_TEST_ENABLED == 'true'", 'always()'],
      ['scheduler', 'scheduler.yml', '--ref production-release', '--ref main'],
      ['target', 'backup-test.yml', 'FE_TARGET: test', 'FE_TARGET: prod'],
      ['runs-on', 'backup-test.yml', 'runs-on: ubuntu-24.04', 'runs-on: self-hosted'],
    ];
    for (const [rule, file, from, to] of cases) assert.ok(rules(file, mutate(file, from, to)).includes(rule), `${rule} via ${file}`);
  });

  test('every environment has exactly one credential family and TEST/PROD families never mix', () => {
    for (const [env, names] of ENVIRONMENT_SECRETS) {
      const t = /^(test|prod)-/.exec(env)?.[1];
      if (t !== undefined) for (const n of names) assert.doesNotMatch(n, new RegExp(t === 'test' ? 'PROD' : 'TEST'), `${env}: ${n}`);
    }
    assert.equal(ENVIRONMENT_SECRETS.size, 15);
  });
});

const M = (sequence: number, extra: Rec = {}): Rec => ({
  schema: 'fine-elements-release-manifest/1', target: 'test', sequence, source_repository: 'gaimeore/fine-elements',
  source_commit: String(sequence).repeat(40).slice(0, 40), source_archive_sha256: 'c'.repeat(64),
  previous_source_commit: sequence === 1 ? null : String(sequence - 1).repeat(40).slice(0, 40), migration_ceiling: '0011_x', ...extra,
});

describe('policy engine — PR classes', () => {
  const history = { test: [M(1), M(2)] as unknown as ReleaseManifest[], prod: [] as ReleaseManifest[] };
  const pr = (changed: Record<string, string | null>, extra: Partial<Parameters<typeof evaluatePullRequest>[0]> = {}) =>
    evaluatePullRequest({ baseRef: 'production-release', headRepoIsBase: true, changed: new Map(Object.entries(changed)), actions: ACTIONS, history, ...extra });

  test('class 1: exactly one manifest with a valid chain passes', () => {
    const verdict = pr({ 'release/test.json': JSON.stringify(M(3)) });
    assert.deepEqual([verdict.pass, verdict.prClass], [true, 1]);
  });

  test('class 1 rejects a broken chain, PROD without a TEST source, both manifests, or a manifest PR into main', () => {
    assert.equal(pr({ 'release/test.json': JSON.stringify(M(5)) }).pass, false);
    assert.equal(pr({ 'release/prod.json': JSON.stringify({ ...M(1), target: 'prod', source_commit: '9'.repeat(40), promoted_from_test_sequence: 2 }) }).pass, false);
    assert.equal(pr({ 'release/prod.json': JSON.stringify({ ...M(1), target: 'prod', source_commit: '2'.repeat(40), promoted_from_test_sequence: 2 }) }).pass, true);
    assert.equal(pr({ 'release/test.json': JSON.stringify(M(3)), 'release/prod.json': '{}' }).pass, false);
    assert.equal(pr({ 'release/test.json': JSON.stringify(M(3)) }, { baseRef: 'main' }).pass, false);
  });

  test('class 2: code only passes; mixed code + manifest is forbidden', () => {
    assert.deepEqual([pr({ 'docs/notes.md': '# notes\n' }).pass, pr({ 'docs/notes.md': '# notes\n' }).prClass], [true, 2]);
    const mixed = pr({ 'release/test.json': JSON.stringify(M(3)), 'runner/x.ts': 'export {};\n' });
    assert.equal(mixed.pass, false);
    assert.ok(mixed.findings.some((f) => f.rule === 'pr-class'));
  });

  test('forks never pass; policy and config files are never removed; a changed workflow is linted at the head', () => {
    assert.equal(pr({ 'docs/notes.md': '#' }, { headRepoIsBase: false }).pass, false);
    assert.equal(pr({ '.github/workflows/policy.yml': null }).pass, false);
    assert.equal(pr({ 'config/actions.json': null }).pass, false);
    assert.equal(pr({ '.github/workflows/backup-test.yml': mutate('backup-test.yml', 'workflow_dispatch:', 'workflow_run:') }).pass, false);
    assert.equal(pr({ 'runner/build/sandbox.ts': readFileSync('runner/build/sandbox.ts', 'utf8').replace("'--network', 'none'", "'--network', 'bridge'") }).pass, false);
  });

  test('the build wrapper keeps its time bound and the forced container removal right after it', () => {
    const wrapper = readFileSync('runner/build/build-wrapper.ts', 'utf8');
    assert.equal(pr({ 'runner/build/build-wrapper.ts': wrapper }).pass, true);
    const cases: [string, string][] = [["'--kill-after=15s', '1200'", "'--kill-after=15s', '86400'"], ["host.run('timeout', [", "host.run('nice', ["], ["['rm', '-f', 'fe-build']", "['ps']"]];
    for (const [from, to] of cases) {
      assert.notEqual(wrapper.replace(from, to), wrapper, from);
      assert.equal(pr({ 'runner/build/build-wrapper.ts': wrapper.replace(from, to) }).pass, false, from);
    }
    assert.equal(pr({ 'runner/build/sandbox.ts': readFileSync('runner/build/sandbox.ts', 'utf8').replace("'--ipc', 'private', '--cgroupns', 'private',", "'--ipc', 'host', '--cgroupns', 'host',") }).pass, false);
  });
});

describe('content scanner', () => {
  test('the whole committed tree is clean', () => {
    const files = new Map<string, string>();
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (['node_modules', '.git', 'handoff'].includes(entry.name)) continue;
        const p = dir === '.' ? entry.name : `${dir}/${entry.name}`;
        if (entry.isDirectory()) walk(p); else files.set(p, readFileSync(p, 'utf8'));
      }
    };
    walk('.');
    assert.deepEqual(evaluateFiles(files, ACTIONS), []);
  });

  test('credentials, real identifiers, private hostnames, private source and disallowed paths are caught', () => {
    const j = (...parts: string[]): string => parts.join('');
    const samples: [string, string, string][] = [
      ['credential', 'docs/a.md', j('-----BEGIN ', 'PRIVATE KEY-----')],
      ['credential', 'docs/a.md', j('gh', 'p_', 'A'.repeat(36))],
      ['credential', 'docs/a.md', j('postgres', '://user:pw', '@host/db')],
      ['private-identifier', 'docs/a.md', j('fine-elements-', 'private-', 'test')],
      ['private-identifier', 'docs/a.md', j('cold', '-darkness-', '23596123')],
      ['private-identifier', 'docs/a.md', j('0b6f3c8e', '-5d1a-4c4e-9f51-', '2f6a0d3b1e01')],
      ['private-identifier', 'docs/a.md', j('fedcba98', '76543210fedcba98', '76543210')],
      ['private-identifier', 'docs/a.md', j('4_z', 'abc123', 'def456abc123def456')],
      ['private-hostname', 'docs/a.md', j('admin.fine-elements', '.gr')],
      ['private-source', 'runner/x.ts', j("import x from '", "react'")],
      ['path-allowlist', 'src/main.tsx', 'x'],
      ['path-allowlist', 'server/migrations/0011.sql', 'x'],
      ['path-allowlist', '.env', 'X=1'],
    ];
    for (const [rule, file, text] of samples) assert.ok(scanContent(file, text).some((f) => f.rule === rule), `${rule}: ${file}`);
  });
});

describe('fe-policy App identity', () => {
  test('the App JWT is RS256, short-lived and verifiable', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwt = appJwt('12345', privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(), 1_800_000_000);
    const [h, p, s] = jwt.split('.');
    assert.deepEqual(JSON.parse(Buffer.from(h!, 'base64url').toString()), { alg: 'RS256', typ: 'JWT' });
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString()) as { iat: number; exp: number; iss: string };
    assert.deepEqual(payload, { iat: 1_799_999_940, exp: 1_800_000_540, iss: '12345' });
    const verifier = createVerify('RSA-SHA256'); verifier.update(`${h}.${p}`);
    assert.ok(verifier.verify(publicKey, Buffer.from(s!, 'base64url')));
    assert.match(summarize({ pass: false, prClass: 2, findings: [{ rule: 'x', path: 'a`b', detail: '<y>' }] }), /PR class: 2/);
  });
});
