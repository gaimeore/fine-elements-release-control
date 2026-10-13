/** Shared library: canonical JSON, job credential split, target config, handoff crypto, manifests, committed tables. */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import { canonicalJson } from '../runner/lib/canonical-json.ts';
import { HANDOFF_SCHEMA, PAD_BUCKET, generateRecipientKeyPair, handoffDigest, openHandoff, privateKeyFromJwk, sealHandoff, type HandoffContext } from '../runner/lib/handoff.ts';
import { JOB_ENV, checkJobEnv, isCredentialName } from '../runner/lib/job-env.ts';
import { parseManifest, validateManifestHistory, validateManifestSuccessor, validateProdPromotion, type ReleaseManifest } from '../runner/lib/manifest.ts';
import { loadRecipientTable, parseRecipientTable, recipientsFor } from '../runner/lib/recipients.ts';
import { CONFIG_FIELDS, loadFingerprintTable, parseFingerprintTable, parseTargetConfig, targetConfigFingerprint, verifiedTargetConfig } from '../runner/lib/target-config.ts';
import { assertReleaseRun, assertReleaseTip, runContextFrom } from '../runner/lib/github.ts';

const hex = (c: string, n = 64): string => c.repeat(n).slice(0, n);

describe('canonical JSON', () => {
  test('sorted keys, no whitespace, stable across insertion order', () => {
    assert.equal(canonicalJson({ b: 1, a: { d: [1, 'x'], c: null } }), '{"a":{"c":null,"d":[1,"x"]},"b":1}');
    assert.equal(canonicalJson({ x: 1, y: 2 }), canonicalJson({ y: 2, x: 1 }));
    assert.throws(() => canonicalJson({ a: Number.NaN }), /non-finite/);
    assert.throws(() => canonicalJson({ a: undefined }), /undefined/);
    assert.throws(() => canonicalJson(new Date()), /plain objects/);
  });
});

describe('job credential split', () => {
  test('each job holds exactly its own family; foreign credential names are refused by name only', () => {
    for (const [kind, names] of Object.entries(JOB_ENV)) {
      const env = Object.fromEntries(names.map((n) => [n, 'v']));
      assert.doesNotThrow(() => checkJobEnv(kind as keyof typeof JOB_ENV, { ...env, PATH: '/bin', GITHUB_RUN_ID: '1', ACTIONS_RUNTIME_TOKEN: 'runner-owned' }), kind);
      assert.throws(() => checkJobEnv(kind as keyof typeof JOB_ENV, { ...env, OTHER_DATABASE_URL: 'secret-value-x' }), (e: Error) => /must not hold: OTHER_DATABASE_URL/.test(e.message) && !e.message.includes('secret-value-x'));
      assert.throws(() => checkJobEnv(kind as keyof typeof JOB_ENV, {}), /requires/);
    }
    for (const name of ['DATABASE_URL', 'X_DATABASE_URL', 'B2_A', 'R2_B', 'CLOUDFLARE_API_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN', 'X_PRIVATE_KEY', 'TARGET_CONFIG_JSON', 'SOURCE_DEPLOY_KEY', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN']) {
      assert.ok(isCredentialName(name), name);
    }
    for (const name of ['PATH', 'FE_TARGET', 'SCAN_DIGEST', 'GITHUB_RUN_ID', 'ACTIONS_RUNTIME_TOKEN', 'CLOUDFLARE_ACCOUNT_ID']) assert.ok(!isCredentialName(name), name);
  });

  test('no job holds two families: verifier, writer, deploy, source and build never overlap where forbidden', () => {
    assert.ok(!JOB_ENV['backup-write'].some((n) => /DATABASE|RESTORE/.test(n)));
    assert.ok(!JOB_ENV['backup-verify'].some((n) => /WRITER|R2_|CLOUDFLARE/.test(n)));
    assert.ok(!JOB_ENV.deploy.some((n) => /B2_|R2_|VERIFIER|SOURCE_DEPLOY/.test(n)));
    assert.deepEqual(JOB_ENV['source-fetch'], ['SOURCE_DEPLOY_KEY']);
    assert.deepEqual(JOB_ENV.build, ['FE_HANDOFF_PRIVATE_KEY']);
  });
});

function config(kind: keyof typeof CONFIG_FIELDS, target: 'test' | 'prod', salt: string, override: Record<string, string> = {}): string {
  const values: Record<string, string> = {
    neon_project_id: `synthetic-project-${target}`, neon_branch_id: `br-synthetic-${target}`, neon_database: 'neondb',
    b2_bucket: `synthetic-backup-${target}`, b2_endpoint: 'https://s3.synthetic-region.example', b2_region: 'synthetic-region',
    destination_prefix: `r2/synthetic-source-${target}/`, cloudflare_account_id: '0123456789abcdef0123456789abcdef',
    r2_source_bucket: `synthetic-source-${target}`, r2_private_media_bucket: `synthetic-media-${target}`,
    deployment_environment_label: target, public_worker_name: `synthetic-worker-${target}`, public_origin: 'https://synthetic.example',
    policy_app_id: '12345', policy_app_installation_id: '67890',
  };
  const fields = Object.fromEntries(CONFIG_FIELDS[kind].map((f) => [f, override[f] ?? values[f]!]));
  return JSON.stringify({ schema: 'fe-target-config/1', kind, target, salt: hex(salt), ...fields });
}

describe('TARGET_CONFIG_JSON', () => {
  test('exact schema per kind: unknown, missing, wrong kind/target, bad salt and malformed fields fail closed', () => {
    const json = config('deploy', 'test', 'a');
    assert.equal(parseTargetConfig(json, 'deploy', 'test').fields.public_worker_name, 'synthetic-worker-test');
    const raw = JSON.parse(json) as Record<string, string>;
    assert.throws(() => parseTargetConfig(JSON.stringify({ ...raw, extra: 'x' }), 'deploy', 'test'), /unknown fields: extra/);
    const { public_worker_name: _omit, ...missing } = raw;
    assert.throws(() => parseTargetConfig(JSON.stringify(missing), 'deploy', 'test'), /missing fields: public_worker_name/);
    assert.throws(() => parseTargetConfig(json, 'verify', 'test'), /unknown fields|missing fields|not a verify config/);
    assert.throws(() => parseTargetConfig(json, 'deploy', 'prod'), /not a prod config/);
    assert.throws(() => parseTargetConfig(JSON.stringify({ ...raw, salt: 'short' }), 'deploy', 'test'), /salt/);
    assert.throws(() => parseTargetConfig(JSON.stringify({ ...raw, cloudflare_account_id: 'ZZ' }), 'deploy', 'test'), /cloudflare_account_id is malformed/);
    assert.throws(() => parseTargetConfig('{', 'deploy', 'test'), /not valid JSON/);
  });

  test('fingerprints are salted, distinct per target, and compared before use; null means not provisioned', () => {
    const testCfg = parseTargetConfig(config('deploy', 'test', 'a'), 'deploy', 'test');
    const prodCfg = parseTargetConfig(config('deploy', 'prod', 'b'), 'deploy', 'prod');
    const resalted = parseTargetConfig(config('deploy', 'test', 'c'), 'deploy', 'test');
    assert.notEqual(targetConfigFingerprint(testCfg), targetConfigFingerprint(prodCfg));
    assert.notEqual(targetConfigFingerprint(testCfg), targetConfigFingerprint(resalted));
    const empty = { 'backup-verify': null, 'backup-write': null, 'deploy-prepare': null, deploy: null, verify: null, 'control-policy': null };
    const table = parseFingerprintTable({ schema: 'fe-target-fingerprints/1', fingerprints: {
      test: { ...empty, deploy: targetConfigFingerprint(testCfg) }, prod: { ...empty, deploy: targetConfigFingerprint(prodCfg) },
    } });
    assert.doesNotThrow(() => verifiedTargetConfig(config('deploy', 'test', 'a'), 'deploy', 'test', table));
    assert.throws(() => verifiedTargetConfig(config('deploy', 'test', 'a', { public_worker_name: 'synthetic-worker-other' }), 'deploy', 'test', table), /fingerprint mismatch/);
    assert.throws(() => verifiedTargetConfig(config('verify', 'test', 'a'), 'verify', 'test', table), /no accepted target fingerprint/);
    assert.throws(() => verifiedTargetConfig(undefined, 'deploy', 'test', table), /required/);
    assert.throws(() => parseFingerprintTable({ schema: 'fe-target-fingerprints/1', fingerprints: { test: { ...empty, deploy: hex('a') }, prod: { ...empty, deploy: hex('a') } } }), /distinct/);
  });

  test('committed table: TEST data-plane kinds provisioned, test/control-policy null; PROD only the accepted control-policy fingerprint', () => {
    const table = loadFingerprintTable();
    for (const [kind, value] of Object.entries(table.prod)) if (kind !== 'control-policy') assert.equal(value, null, `prod/${kind}`);
    assert.equal(table.prod['control-policy'], '7ba9e881e79b7d73ae724917f3cc195e2f62422b7c4158c2909e4f70c299f32a');
    assert.equal(table.test['control-policy'], null);
    for (const kind of ['backup-verify', 'backup-write', 'deploy-prepare', 'deploy', 'verify'] as const) assert.match(table.test[kind] ?? '', /^[0-9a-f]{64}$/, `test/${kind}`);
  });
});

function ctx(overrides: Partial<HandoffContext> = {}): HandoffContext {
  return { repository: 'gaimeore/fine-elements-release-control', workflowRef: 'gaimeore/fine-elements-release-control/.github/workflows/deploy-test.yml@refs/heads/production-release', target: 'test', runId: '100', runAttempt: '1', producerJob: 'build', artifact: 'bundle', bindings: { source_commit: hex('a', 40), manifest_sequence: '3' }, ...overrides };
}

describe('encrypted handoffs (X25519 → HKDF-SHA256 → AES-256-GCM)', () => {
  const deploy = generateRecipientKeyPair();
  const verify = generateRecipientKeyPair();
  const other = generateRecipientKeyPair();
  const recipients = [{ name: 'test/deploy', x: deploy.x }, { name: 'test/verify', x: verify.x }];
  const plaintext = Buffer.from('synthetic bundle bytes', 'utf8');
  const envelope = sealHandoff(plaintext, recipients, ctx());
  const digest = handoffDigest(envelope);

  test('every recipient opens it; the envelope never contains the plaintext; size is padded', () => {
    assert.deepEqual(openHandoff(envelope, digest, privateKeyFromJwk(deploy.privateJwk), ctx()), plaintext);
    assert.deepEqual(openHandoff(envelope, digest, privateKeyFromJwk(verify.privateJwk), ctx()), plaintext);
    assert.ok(!envelope.includes(plaintext));
    assert.equal((JSON.parse(envelope.toString('utf8')) as { schema: string }).schema, HANDOFF_SCHEMA);
    assert.ok(Buffer.from((JSON.parse(envelope.toString('utf8')) as { ciphertext: string }).ciphertext, 'base64').length >= PAD_BUCKET);
  });

  test('wrong key, target, run, attempt, producer, artifact or binding are rejected', () => {
    const key = privateKeyFromJwk(deploy.privateJwk);
    assert.throws(() => openHandoff(envelope, digest, privateKeyFromJwk(other.privateJwk), ctx()), /not addressed to this environment/);
    for (const bad of [{ target: 'prod' }, { runId: '101' }, { runAttempt: '2' }, { producerJob: 'deploy' }, { artifact: 'bundle-files' }, { bindings: { source_commit: hex('b', 40), manifest_sequence: '3' } }, { workflowRef: 'x' }]) {
      assert.throws(() => openHandoff(envelope, digest, key, ctx(bad)), /authentication failed/, JSON.stringify(bad));
    }
  });

  test('tampering and artifact substitution fail before or at decryption', () => {
    const key = privateKeyFromJwk(deploy.privateJwk);
    const tampered = JSON.parse(envelope.toString('utf8')) as Record<string, string>;
    const ct = Buffer.from(tampered.ciphertext!, 'base64');
    ct[10] = ct[10]! ^ 0xff;
    const tamperedEnvelope = Buffer.from(JSON.stringify({ ...tampered, ciphertext: ct.toString('base64') }), 'utf8');
    assert.throws(() => openHandoff(tamperedEnvelope, digest, key, ctx()), /digest does not match/);
    assert.throws(() => openHandoff(tamperedEnvelope, handoffDigest(tamperedEnvelope), key, ctx()), /authentication failed/);
    const substitute = sealHandoff(Buffer.from('attacker bytes'), recipients, ctx());
    assert.throws(() => openHandoff(substitute, digest, key, ctx()), /digest does not match/);
    assert.throws(() => openHandoff(envelope, 'nothex', key, ctx()), /malformed/);
  });

  test('keys are X25519 JWKs; anything else fails closed', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
    assert.throws(() => privateKeyFromJwk(JSON.stringify(rsa)), /X25519 JWK/);
    assert.throws(() => privateKeyFromJwk('not json'), /not a JWK/);
    assert.throws(() => sealHandoff(plaintext, [], ctx()), /at least one recipient/);
  });

  test('committed recipients: TEST has exactly the six distinct public keys; every PROD recipient is null and fails closed', () => {
    const table = loadRecipientTable();
    assert.throws(() => recipientsFor(table, 'prod', ['deploy']), /not provisioned/);
    for (const value of Object.values(table.prod)) assert.equal(value, null);
    const testKeys = recipientsFor(table, 'test', ['backup-verify', 'backup-write', 'build', 'deploy', 'verify', 'audit']).map((r) => r.x);
    assert.equal(new Set(testKeys).size, 6);
    assert.throws(() => parseRecipientTable({ schema: 'fe-recipients/1', recipients: { test: {} } }), /exactly test and prod/);
  });
});

function manifest(overrides: Partial<ReleaseManifest> & { sequence: number }): Record<string, unknown> {
  return {
    schema: 'fine-elements-release-manifest/1', target: 'test', source_repository: 'gaimeore/fine-elements',
    source_commit: hex(String(overrides.sequence), 40), source_archive_sha256: hex('c'), previous_source_commit: overrides.sequence === 1 ? null : hex(String(overrides.sequence - 1), 40),
    migration_ceiling: '0011_live_catalogue_control', ...overrides,
  };
}

describe('release manifests', () => {
  test('exact schema: 40-hex commit, 64-hex archive, chain fields, prod promotion field', () => {
    assert.equal(parseManifest(manifest({ sequence: 1 })).sequence, 1);
    for (const bad of [
      { ...manifest({ sequence: 1 }), extra: 1 },
      manifest({ sequence: 1, source_commit: 'main' }),
      manifest({ sequence: 1, source_commit: hex('A', 40) }),
      manifest({ sequence: 1, source_archive_sha256: hex('c', 63) }),
      manifest({ sequence: 2, previous_source_commit: null }),
      manifest({ sequence: 1, previous_source_commit: hex('9', 40) }),
      manifest({ sequence: 1, source_repository: 'gaimeore/other' as 'gaimeore/fine-elements' }),
      manifest({ sequence: 1, migration_ceiling: '11' }),
      { ...manifest({ sequence: 1 }), target: 'prod' },
      manifest({ sequence: 0 }),
    ]) assert.throws(() => parseManifest(bad), JSON.stringify(bad).slice(0, 80));
    assert.throws(() => parseManifest(manifest({ sequence: 1 }), 'prod'), /must be prod/);
  });

  test('the chain increases by exactly one and links the previous source commit', () => {
    const history = [1, 2, 3].map((n) => parseManifest(manifest({ sequence: n })));
    assert.doesNotThrow(() => validateManifestHistory(history));
    assert.throws(() => validateManifestSuccessor(history[2]!, parseManifest(manifest({ sequence: 5 }))), /exactly 1/);
    assert.throws(() => validateManifestSuccessor(history[2]!, parseManifest({ ...manifest({ sequence: 4 }), previous_source_commit: hex('9', 40) })), /previous_source_commit/);
    assert.throws(() => validateManifestSuccessor(null, parseManifest(manifest({ sequence: 2 }))), /sequence 1/);
  });

  test('PROD deploys only a source TEST had', () => {
    const tests = [1, 2].map((n) => parseManifest(manifest({ sequence: n })));
    const prod = (seq: number, commit: string): ReleaseManifest => parseManifest({ ...manifest({ sequence: 1 }), target: 'prod', source_commit: commit, promoted_from_test_sequence: seq });
    assert.doesNotThrow(() => validateProdPromotion(prod(2, hex('2', 40)), tests));
    assert.throws(() => validateProdPromotion(prod(2, hex('1', 40)), tests), /does not match/);
    assert.throws(() => validateProdPromotion(prod(7, hex('2', 40)), tests), /not in the TEST history/);
  });
});

describe('release-run guards', () => {
  const env = {
    GITHUB_REPOSITORY: 'gaimeore/fine-elements-release-control',
    GITHUB_WORKFLOW_REF: 'gaimeore/fine-elements-release-control/.github/workflows/backup-test.yml@refs/heads/production-release',
    GITHUB_RUN_ID: '1', GITHUB_RUN_ATTEMPT: '1', GITHUB_SHA: hex('d', 40), GITHUB_REF: 'refs/heads/production-release',
  };
  test('privileged jobs run only from production-release of this repository', () => {
    assert.doesNotThrow(() => assertReleaseRun(runContextFrom(env)));
    assert.throws(() => assertReleaseRun(runContextFrom({ ...env, GITHUB_REF: 'refs/heads/main' })), /only on production-release/);
    assert.throws(() => assertReleaseRun(runContextFrom({ ...env, GITHUB_REPOSITORY: 'someone/fork' })), /not the release-control repository/);
    assert.throws(() => assertReleaseRun(runContextFrom({ ...env, GITHUB_WORKFLOW_REF: env.GITHUB_WORKFLOW_REF.replace('production-release', 'main') })), /does not come from production-release/);
  });

  test('a re-run at a stale SHA stops: the release tip must equal GITHUB_SHA', async () => {
    const tip = (sha: string) => (async () => new Response(JSON.stringify({ object: { sha } }), { status: 200 })) as typeof fetch;
    await assert.doesNotReject(assertReleaseTip(runContextFrom(env), 't', tip(hex('d', 40))));
    await assert.rejects(assertReleaseTip(runContextFrom(env), 't', tip(hex('e', 40))), /not at the current production-release tip/);
  });
});

test('committed config files parse', () => {
  assert.doesNotThrow(() => parseFingerprintTable(JSON.parse(readFileSync('config/target-fingerprints.json', 'utf8'))));
  assert.doesNotThrow(() => parseRecipientTable(JSON.parse(readFileSync('config/recipients.json', 'utf8'))));
});
