/**
 * Fine Elements — automated master backup lane (offline). Ported with the
 * lane from the private source repository (S12K-D2, 60 tests) at RC2.
 *
 * Fakes only: no B2, R2 or database network call. The fake ledger enforces
 * migration 0011's master_backup rules (append-only, primary key, one
 * verified per master, verified/mismatch CHECKs) so a lane bug cannot hide
 * behind a permissive fake.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, test } from 'node:test';

import type { S3Client } from '@aws-sdk/client-s3';

import type { AuthoritativeMaster, MasterBackupRecord, NewMasterBackup } from '../runner/backup/ledger.ts';
import {
  CREDENTIAL_ENV,
  checkCredentialEnv,
  parseBackupCliArgs,
  r2SourceClientFor,
} from '../runner/backup/backup-cli.ts';
import {
  assertBackupTarget,
  backupTargetFromConfig,
  classifyMaster,
  destinationKeyFor,
  evaluateExactVersion,
  finalLaneIsGreen,
  laneIsGreen,
  parseScanReport,
  parseScanReportForWriter,
  parseVerifyInputs,
  runFinalCoverage,
  runVerifyAgain,
  runVerifyScan,
  runWriteMissing,
  type B2VersionEntry,
  type BackupLedger,
  type BackupObjectWriter,
  type BackupTarget,
  type BackupVersionReader,
  type MasterSourceReader,
  type ObservedVersion,
  type RunIdentity,
  type WriteReport,
} from '../runner/backup/master-backup-lane.ts';
import {
  B2MinimalWriter,
  B2RestoreReader,
  R2MasterSource,
  createB2Client,
  createB2WriterClient,
} from '../runner/backup/s3-backup-adapters.ts';
import { parseTarget, parseTargetConfig, targetConfigFingerprint, verifiedTargetConfig } from '../runner/lib/target-config.ts';

/** Synthetic target: the public repository never carries real resource identifiers. */
const TARGET: BackupTarget = Object.freeze({
  name: 'test',
  sourceBucket: 'synthetic-source-test',
  b2Bucket: 'synthetic-backup-test',
  destinationPrefix: 'r2/synthetic-source-test/',
  b2Endpoint: 'https://s3.synthetic-region.example',
  b2Region: 'synthetic-region',
});
const RUN: RunIdentity = { runId: '9001', runAttempt: '1' };
const KEY_A = 'masters/sample-collection/00000000-0000-4000-8000-0000000000a1.png';
const KEY_B = 'masters/site/00000000-0000-4000-8000-0000000000b2.jpg';

const sha = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const bytesOf = (text: string): Uint8Array => new TextEncoder().encode(text);
const masterOf = (masterKey: string, bytes: Uint8Array): AuthoritativeMaster => ({
  masterKey,
  contentHash: sha(bytes),
  masterBytes: bytes.byteLength,
});
const roundTrip = <T>(value: T): unknown => JSON.parse(JSON.stringify(value)) as unknown;

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

class FakeLedger implements BackupLedger {
  readonly rows: MasterBackupRecord[] = [];
  readonly inserts: NewMasterBackup[] = [];
  failInsert = false;

  masters: AuthoritativeMaster[];
  constructor(masters: AuthoritativeMaster[]) { this.masters = masters; }

  async listAuthoritativeMasters(): Promise<readonly AuthoritativeMaster[]> {
    return [...this.masters];
  }

  async findAuthoritativeMasters(masterKey: string): Promise<readonly AuthoritativeMaster[]> {
    return this.masters.filter((m) => m.masterKey === masterKey);
  }

  async listBackups(masterKey: string): Promise<readonly MasterBackupRecord[]> {
    return this.rows.filter((r) => r.masterKey === masterKey);
  }

  async insertBackup(row: NewMasterBackup): Promise<MasterBackupRecord> {
    if (this.failInsert) throw new Error('connection reset');
    // migration 0011 master_backup rules
    assert.ok(this.rows.every((r) => !(r.masterKey === row.masterKey && r.b2VersionId === row.b2VersionId)), 'master_backup_pkey');
    if (row.state === 'verified') {
      assert.ok(this.rows.every((r) => !(r.masterKey === row.masterKey && r.state === 'verified')), 'master_backup_one_verified_per_master');
      assert.ok(row.observedSha256 === row.sourceSha256 && row.observedBytes === row.sourceBytes, 'master_backup_verified_match_check');
    } else {
      assert.ok(row.observedSha256 === null || row.observedSha256 !== row.sourceSha256 || row.observedBytes !== row.sourceBytes, 'master_backup_mismatch_differs_check');
    }
    assert.equal(row.observedSha256 === null, row.observedBytes === null, 'master_backup_observed_pair_check');
    assert.ok(row.observedBytes === null || row.observedBytes > 0, 'master_backup_observed_bytes_positive_check');
    this.inserts.push(row);
    const record = { ...row, recordedAt: new Date(Date.UTC(2026, 9, 13, 0, 0, this.rows.length)).toISOString() };
    this.rows.push(record);
    return record;
  }
}

/** A versioned bucket: a PUT appends a version, nothing is ever replaced. */
class FakeB2 implements BackupVersionReader, BackupObjectWriter {
  readonly objects = new Map<string, { versionId: string; bytes: Uint8Array }[]>();
  readonly deleteMarkers = new Set<string>();
  readonly puts: { key: string; contentMd5Base64: string }[] = [];
  readonly reads: { key: string; versionId: string }[] = [];
  returnVersionId = true;
  failReads = false;
  #next = 1;

  seed(key: string, bytes: Uint8Array): string {
    const versionId = `4_z000000000000000000000000_f${String(this.#next++).padStart(4, '0')}`;
    this.objects.set(key, [...(this.objects.get(key) ?? []), { versionId, bytes }]);
    return versionId;
  }

  async putObject(input: { key: string; bytes: Uint8Array; contentMd5Base64: string; contentType: string }): Promise<{ versionId: string | null }> {
    this.puts.push({ key: input.key, contentMd5Base64: input.contentMd5Base64 });
    const versionId = this.seed(input.key, input.bytes);
    return { versionId: this.returnVersionId ? versionId : null };
  }

  async listVersions(prefix: string): Promise<readonly B2VersionEntry[]> {
    const entries: B2VersionEntry[] = [];
    for (const [key, versions] of this.objects) {
      if (!key.startsWith(prefix)) continue;
      for (const v of versions) entries.push({ key, versionId: v.versionId, kind: 'version' });
    }
    for (const key of this.deleteMarkers) if (key.startsWith(prefix)) entries.push({ key, versionId: `dm-${key}`, kind: 'delete_marker' });
    return entries;
  }

  async getVersion(key: string, versionId: string): Promise<ObservedVersion | null> {
    this.reads.push({ key, versionId });
    if (this.failReads) throw new Error('socket hang up');
    const found = this.objects.get(key)?.find((v) => v.versionId === versionId);
    return found === undefined ? null : { bytes: found.bytes, versionId };
  }
}

class FakeSource implements MasterSourceReader {
  readonly masters: Map<string, Uint8Array>;
  constructor(masters: Map<string, Uint8Array>) { this.masters = masters; }
  async getMaster(masterKey: string): Promise<{ bytes: Uint8Array; contentType: string | null } | null> {
    const bytes = this.masters.get(masterKey);
    return bytes === undefined ? null : { bytes, contentType: 'image/png' };
  }
}

async function runLane(ledger: FakeLedger, b2: FakeB2, source: FakeSource, run: RunIdentity = RUN) {
  const scan = await runVerifyScan({ target: TARGET, ledger, reader: b2 }, run);
  const plan = parseScanReportForWriter(roundTrip(scan), TARGET, run);
  const written = await runWriteMissing({ target: TARGET, source, writer: b2 }, plan);
  const inputs = parseVerifyInputs(roundTrip(scan), roundTrip(written), TARGET, run);
  const verify = await runVerifyAgain({ target: TARGET, ledger, reader: b2 }, inputs.written);
  const coverage = await runFinalCoverage({ target: TARGET, ledger, reader: b2 });
  return { scan, scanParsed: inputs.scan, written, verify, coverage, green: finalLaneIsGreen(inputs.scan, verify, coverage) };
}

// ---------------------------------------------------------------------------

describe('S12K-D — 1. deterministic TEST destination key', () => {
  test('r2/<R2 bucket>/<R2 master key>, one convention for photographs and site images', () => {
    assert.equal(destinationKeyFor(TARGET, KEY_A), `r2/synthetic-source-test/${KEY_A}`);
    assert.equal(destinationKeyFor(TARGET, KEY_B), `r2/synthetic-source-test/${KEY_B}`);
    assert.ok(destinationKeyFor(TARGET, KEY_A).startsWith('r2/synthetic-source-test/masters/'));
    assert.equal(destinationKeyFor(TARGET, KEY_A), destinationKeyFor(TARGET, KEY_A));
  });

  test('keys outside masters/ or with traversal / odd characters are refused', () => {
    for (const bad of ['', 'masters/', 'masters/a', '/masters/a/b.png', 'renditions/a/b.webp', 'masters/../x/b.png',
      'masters/./b.png', 'masters/a//b.png', 'masters/a b/c.png', 'masters\\a\\b.png', 'masters/a/b.png\n']) {
      assert.throws(() => destinationKeyFor(TARGET, bad), /valid masters\/ key/, JSON.stringify(bad));
    }
  });
});

describe('S12K-D — verify-scan classification', () => {
  test('2. an already-verified master is skipped and never reaches the writer', async () => {
    const bytes = bytesOf('verified master');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const versionId = b2.seed(destinationKeyFor(TARGET, KEY_A), bytes);
    await ledger.insertBackup({ masterKey: KEY_A, b2VersionId: versionId, state: 'verified', sourceSha256: sha(bytes), sourceBytes: bytes.byteLength, observedSha256: sha(bytes), observedBytes: bytes.byteLength });

    const { scan, written, green } = await runLane(ledger, b2, new FakeSource(new Map([[KEY_A, bytes]])));
    assert.equal(scan.decisions[0]?.scanClass, 'already_verified');
    assert.equal(scan.decisions[0]?.versionId, versionId);
    assert.deepEqual(scan.candidates, []);
    assert.deepEqual(written.results, []);
    assert.equal(b2.puts.length, 0);
    assert.equal(green, true);
  });

  test('3. a genuinely missing master becomes the only kind of write candidate', async () => {
    const bytes = bytesOf('new master');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const scan = await runVerifyScan({ target: TARGET, ledger, reader: new FakeB2() }, RUN);
    assert.equal(scan.decisions[0]?.scanClass, 'missing');
    assert.deepEqual(scan.candidates, [{ masterKey: KEY_A, destinationKey: `r2/synthetic-source-test/${KEY_A}`, sourceSha256: sha(bytes), sourceBytes: bytes.byteLength }]);
  });

  test('4. an existing B2 version without DB proof is NOT missing: verify-scan evaluates that exact version instead', async () => {
    const bytes = bytesOf('manually backed up master');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const versionId = b2.seed(destinationKeyFor(TARGET, KEY_A), bytes);

    const scan = await runVerifyScan({ target: TARGET, ledger, reader: b2 }, RUN);
    assert.equal(scan.decisions[0]?.scanClass, 'existing_unproven');
    assert.deepEqual(scan.candidates, []);
    assert.deepEqual(b2.reads, [{ key: destinationKeyFor(TARGET, KEY_A), versionId }]);
    assert.equal(scan.decisions[0]?.evaluation?.outcome, 'verified');
    assert.equal(ledger.rows[0]?.b2VersionId, versionId);
    assert.equal(b2.puts.length, 0);
  });

  test('4b. several versions without proof, or a delete marker, are unsafe and not written', () => {
    const master = masterOf(KEY_A, bytesOf('x'));
    const key = destinationKeyFor(TARGET, KEY_A);
    const v = (versionId: string, kind: B2VersionEntry['kind'] = 'version'): B2VersionEntry => ({ key, versionId, kind });
    assert.deepEqual(classifyMaster(master, [], [v('1'), v('2')]), { scanClass: 'unsafe', reason: 'multiple_versions_without_proof', versionId: null });
    assert.deepEqual(classifyMaster(master, [], [v('1'), v('d', 'delete_marker')]), { scanClass: 'unsafe', reason: 'delete_marker_present', versionId: null });
    assert.deepEqual(classifyMaster(master, [], [v('d', 'delete_marker')]), { scanClass: 'unsafe', reason: 'delete_marker_present', versionId: null });
  });

  test('4c. a verified proof that disagrees with the master, or whose version is gone from B2, is unsafe', () => {
    const bytes = bytesOf('m');
    const master = masterOf(KEY_A, bytes);
    const key = destinationKeyFor(TARGET, KEY_A);
    const proof: MasterBackupRecord = { masterKey: KEY_A, b2VersionId: 'v1', state: 'verified', sourceSha256: sha(bytes), sourceBytes: 1, observedSha256: sha(bytes), observedBytes: 1, recordedAt: '2026-10-13T00:00:00.000Z' };
    assert.equal(classifyMaster(master, [proof], [{ key, versionId: 'v1', kind: 'version' }]).scanClass, 'already_verified');
    assert.equal(classifyMaster(master, [proof], []).reason, 'verified_version_absent_from_b2');
    assert.equal(classifyMaster({ ...master, masterBytes: 2 }, [proof], [{ key, versionId: 'v1', kind: 'version' }]).reason, 'verified_proof_conflicts_with_master');
  });

  test('a B2 listing failure is indeterminate for every master, never "missing"', async () => {
    const ledger = new FakeLedger([masterOf(KEY_A, bytesOf('a'))]);
    const reader = new FakeB2();
    reader.listVersions = async () => { throw new Error('503'); };
    const scan = await runVerifyScan({ target: TARGET, ledger, reader }, RUN);
    assert.equal(scan.decisions[0]?.scanClass, 'indeterminate');
    assert.deepEqual(scan.candidates, []);
  });

  test('a key that only shares a prefix with the master key does not count as its object', async () => {
    const bytes = bytesOf('a');
    const b2 = new FakeB2();
    b2.seed(`${destinationKeyFor(TARGET, KEY_A)}.bak`, bytes);
    const scan = await runVerifyScan({ target: TARGET, ledger: new FakeLedger([masterOf(KEY_A, bytes)]), reader: b2 }, RUN);
    assert.equal(scan.decisions[0]?.scanClass, 'missing');
  });
});

describe('S12K-D — 5. a mismatch never reaches the writer', () => {
  test('an existing version with different bytes is recorded as mismatch and is never planned for writing, now or later', async () => {
    const bytes = bytesOf('authoritative');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    b2.seed(destinationKeyFor(TARGET, KEY_A), bytesOf('corrupted copy'));
    const source = new FakeSource(new Map([[KEY_A, bytes]]));

    const first = await runLane(ledger, b2, source);
    assert.equal(first.scan.decisions[0]?.evaluation?.outcome, 'mismatch');
    assert.equal(ledger.rows[0]?.state, 'mismatch');
    assert.deepEqual(first.scan.candidates, []);
    assert.equal(first.green, false);

    const second = await runLane(ledger, b2, source, { runId: '9002', runAttempt: '1' });
    assert.equal(second.scan.decisions[0]?.reason, 'mismatch_recorded');
    assert.deepEqual(second.scan.candidates, []);
    assert.equal(b2.puts.length, 0);
    assert.equal(b2.objects.get(destinationKeyFor(TARGET, KEY_A))?.length, 1);
  });
});

describe('S12K-D — write-missing and verify-again', () => {
  test('6. PutObject without a VersionId fails closed: no master_backup row, lane not green', async () => {
    const bytes = bytesOf('new');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    b2.returnVersionId = false;
    const { written, verify, green } = await runLane(ledger, b2, new FakeSource(new Map([[KEY_A, bytes]])));
    assert.equal(written.results[0]?.status, 'failed');
    assert.equal(written.results[0]?.reason, 'put_without_version_id');
    assert.equal(verify.results[0]?.outcome, 'not_written');
    assert.deepEqual(ledger.rows, []);
    assert.equal(b2.reads.length, 0);
    assert.equal(green, false);
  });

  test('6b. the B2 writer adapter maps an absent or blank VersionId to null', async () => {
    for (const VersionId of [undefined, '', '  ']) {
      const client = { send: async () => ({ VersionId }) } as unknown as S3Client;
      const out = await new B2MinimalWriter(client, TARGET).putObject({ key: destinationKeyFor(TARGET, KEY_A), bytes: bytesOf('x'), contentMd5Base64: 'bWQ1', contentType: 'image/png' });
      assert.equal(out.versionId, null);
    }
  });

  test('7. verify-again reads back exactly the VersionId PutObject returned', async () => {
    const bytes = bytesOf('new master bytes');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const { written, verify } = await runLane(ledger, b2, new FakeSource(new Map([[KEY_A, bytes]])));
    const versionId = written.results[0]?.versionId;
    assert.ok(versionId);
    assert.deepEqual(b2.reads, [{ key: destinationKeyFor(TARGET, KEY_A), versionId }]);
    assert.equal(verify.results[0]?.versionId, versionId);
    assert.equal(ledger.rows[0]?.b2VersionId, versionId);
  });

  test('7b. the restore-reader adapter sends GetObject with that exact VersionId and refuses a blank one', async () => {
    const sent: { name: string; input: Record<string, unknown> }[] = [];
    const client = {
      send: async (command: { constructor: { name: string }; input: Record<string, unknown> }) => {
        sent.push({ name: command.constructor.name, input: command.input });
        return { Body: bytesOf('abc'), VersionId: '4_zEXACT' };
      },
    } as unknown as S3Client;
    const reader = new B2RestoreReader(client, TARGET);
    const observed = await reader.getVersion('r2/synthetic-source-test/masters/a/b.png', '4_zEXACT');
    assert.deepEqual(sent, [{ name: 'GetObjectCommand', input: { Bucket: TARGET.b2Bucket, Key: 'r2/synthetic-source-test/masters/a/b.png', VersionId: '4_zEXACT' } }]);
    assert.equal(observed?.versionId, '4_zEXACT');
    await assert.rejects(reader.getVersion('r2/synthetic-source-test/masters/a/b.png', ' '), /versionId must be a non-blank/);
  });

  test('7c. only NoSuchKey/NoSuchVersion count as "absent"; any other read error stays indeterminate', async () => {
    const failing = (name: string) => new B2RestoreReader({ send: async () => { const e = new Error(name); e.name = name; throw e; } } as unknown as S3Client, TARGET);
    assert.equal(await failing('NoSuchVersion').getVersion('k', 'v'), null);
    assert.equal(await failing('NoSuchKey').getVersion('k', 'v'), null);
    await assert.rejects(failing('NoSuchBucket').getVersion('k', 'v'));
    await assert.rejects(failing('AccessDenied').getVersion('k', 'v'));
  });

  test('8. exact bytes and SHA-256 match → one verified row bound to the exact VersionId', async () => {
    const bytes = bytesOf('exact');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const { verify, green } = await runLane(ledger, b2, new FakeSource(new Map([[KEY_A, bytes]])));
    assert.equal(verify.results[0]?.outcome, 'verified');
    assert.equal(verify.results[0]?.recorded, true);
    assert.equal(green, true);
    assert.deepEqual(ledger.inserts, [{
      masterKey: KEY_A, b2VersionId: verify.results[0]?.versionId, state: 'verified',
      sourceSha256: sha(bytes), sourceBytes: bytes.byteLength, observedSha256: sha(bytes), observedBytes: bytes.byteLength,
    }]);
  });

  test('9. a byte-count mismatch is not verified (recorded as mismatch)', async () => {
    const stored = bytesOf('0123456789');
    const master: AuthoritativeMaster = { masterKey: KEY_A, contentHash: sha(stored), masterBytes: 11 };
    const ledger = new FakeLedger([master]);
    const b2 = new FakeB2();
    const versionId = b2.seed(destinationKeyFor(TARGET, KEY_A), stored);
    const evaluation = await evaluateExactVersion(ledger, b2, master, destinationKeyFor(TARGET, KEY_A), versionId);
    assert.equal(evaluation.outcome, 'mismatch');
    assert.equal(ledger.rows[0]?.state, 'mismatch');
    assert.equal(ledger.rows[0]?.observedSha256, sha(stored));
    assert.equal(ledger.rows[0]?.observedBytes, 10);
  });

  test('10. a SHA-256 mismatch with equal length is not verified (recorded as mismatch)', async () => {
    const source = bytesOf('aaaaaaaaaa');
    const stored = bytesOf('aaaaaaaaab');
    const ledger = new FakeLedger([masterOf(KEY_A, source)]);
    const b2 = new FakeB2();
    const written: WriteReport = {
      kind: 's12k-backup-write', version: 1, target: 'test', run: RUN,
      results: [{ masterKey: KEY_A, destinationKey: destinationKeyFor(TARGET, KEY_A), sourceSha256: sha(source), sourceBytes: 10, status: 'written', versionId: b2.seed(destinationKeyFor(TARGET, KEY_A), stored), reason: null }],
    };
    const verify = await runVerifyAgain({ target: TARGET, ledger, reader: b2 }, written);
    assert.equal(verify.results[0]?.outcome, 'mismatch');
    assert.equal(ledger.rows[0]?.state, 'mismatch');
    assert.equal(ledger.rows[0]?.observedSha256, sha(stored));
    assert.equal(ledger.rows[0]?.observedBytes, 10);
    assert.equal(b2.puts.length, 0);
  });

  test('a version B2 reports absent is recorded as an unobservable mismatch; a transient read failure records nothing', async () => {
    const bytes = bytesOf('x1');
    const master = masterOf(KEY_A, bytes);
    const key = destinationKeyFor(TARGET, KEY_A);

    const flaky = new FakeB2();
    flaky.failReads = true;
    const ledger1 = new FakeLedger([master]);
    assert.equal((await evaluateExactVersion(ledger1, flaky, master, key, 'v-x')).outcome, 'indeterminate');
    assert.deepEqual(ledger1.rows, []);

    const ledger2 = new FakeLedger([master]);
    const gone = await evaluateExactVersion(ledger2, new FakeB2(), master, key, 'v-gone');
    assert.equal(gone.outcome, 'mismatch');
    assert.deepEqual([ledger2.rows[0]?.observedSha256, ledger2.rows[0]?.observedBytes], [null, null]);
  });
});

describe('S12K-D — 11. the source changing between scan, write and verify fails closed', () => {
  test('R2 bytes differ from the scanned master → no PUT', async () => {
    const bytes = bytesOf('scanned');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const { written, verify, green } = await runLane(ledger, b2, new FakeSource(new Map([[KEY_A, bytesOf('changed!')]])));
    assert.equal(written.results[0]?.reason, 'source_changed');
    assert.equal(b2.puts.length, 0);
    assert.equal(verify.results[0]?.outcome, 'not_written');
    assert.deepEqual(ledger.rows, []);
    assert.equal(green, false);
  });

  test('R2 source missing → no PUT', async () => {
    const ledger = new FakeLedger([masterOf(KEY_A, bytesOf('a'))]);
    const b2 = new FakeB2();
    const { written } = await runLane(ledger, b2, new FakeSource(new Map()));
    assert.equal(written.results[0]?.reason, 'source_missing');
    assert.equal(b2.puts.length, 0);
  });

  test('authoritative DB master changed after the write → verify-again records nothing', async () => {
    const bytes = bytesOf('original');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const scan = await runVerifyScan({ target: TARGET, ledger, reader: b2 }, RUN);
    const written = await runWriteMissing({ target: TARGET, source: new FakeSource(new Map([[KEY_A, bytes]])), writer: b2 }, scan);
    ledger.masters = [masterOf(KEY_A, bytesOf('different master'))];
    const verify = await runVerifyAgain({ target: TARGET, ledger, reader: b2 }, written);
    assert.equal(verify.results[0]?.outcome, 'unsafe');
    assert.equal(verify.results[0]?.reason, 'source_changed');
    assert.deepEqual(ledger.rows, []);
  });

  test('an object that appeared after the scan (a second version) fails closed in verify-again', async () => {
    const bytes = bytesOf('raced');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const scan = await runVerifyScan({ target: TARGET, ledger, reader: b2 }, RUN);
    b2.seed(destinationKeyFor(TARGET, KEY_A), bytes); // concurrent writer
    const written = await runWriteMissing({ target: TARGET, source: new FakeSource(new Map([[KEY_A, bytes]])), writer: b2 }, scan);
    const verify = await runVerifyAgain({ target: TARGET, ledger, reader: b2 }, written);
    assert.equal(verify.results[0]?.reason, 'conflicting_version_present');
    assert.deepEqual(ledger.rows, []);
  });

  test('conflicting DB proof for another version fails closed in verify-again', async () => {
    const bytes = bytesOf('dbconflict');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const scan = await runVerifyScan({ target: TARGET, ledger, reader: b2 }, RUN);
    const written = await runWriteMissing({ target: TARGET, source: new FakeSource(new Map([[KEY_A, bytes]])), writer: b2 }, scan);
    await ledger.insertBackup({ masterKey: KEY_A, b2VersionId: 'other', state: 'mismatch', sourceSha256: sha(bytes), sourceBytes: bytes.byteLength, observedSha256: null, observedBytes: null });
    const verify = await runVerifyAgain({ target: TARGET, ledger, reader: b2 }, written);
    assert.equal(verify.results[0]?.reason, 'ledger_proof_conflict');
    assert.equal(ledger.rows.length, 1);
  });
});

// ---------------------------------------------------------------------------
// 12. Static inspection
// ---------------------------------------------------------------------------

const BACKUP_SOURCES = readdirSync('runner/backup').filter((f) => f.endsWith('.ts')).map((f) => `runner/backup/${f}`);
// S12K-RC1P: the private backup workflows were removed; the release-control
// repository becomes the one backup authority, and its RC2 workflows carry
// their own static checks there.

describe('S12K-D — 12. no delete, hide or bucket/key mutation exists in the backup lane', () => {
  test('the backup sources name no dangerous operation', () => {
    const dangerous = [
      /DeleteObjects?/, /DeleteBucket/, /CopyObject/, /PutBucket/, /CreateBucket/, /RestoreObject/,
      /PutObjectRetention/, /PutObjectLegalHold/, /BypassGovernance/i,
      /b2_hide_file/, /b2_delete_file_version/, /b2_delete_bucket/, /b2_update_bucket/, /b2_create_bucket/,
      /b2_create_key/, /b2_delete_key/, /hide_?file/i, /\bb2\s+(rm|delete|hide|update-bucket|create-key|delete-key)/,
    ];
    assert.ok(BACKUP_SOURCES.length === 4, BACKUP_SOURCES.join(','));
    for (const file of BACKUP_SOURCES) {
      const source = readFileSync(file, 'utf8');
      for (const pattern of dangerous) assert.doesNotMatch(source, pattern, `${file} ${pattern}`);
    }
  });

  test('the only S3 SDK symbols imported are S3Client and the three allowed commands', () => {
    const imported = new Set<string>();
    for (const file of BACKUP_SOURCES) {
      const source = readFileSync(file, 'utf8');
      for (const match of source.matchAll(/import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*'@aws-sdk\/client-s3'/g)) {
        for (const name of match[1]!.split(',').map((s) => s.trim()).filter(Boolean)) imported.add(name);
      }
      assert.doesNotMatch(source, /require\(\s*['"]@aws-sdk/, file);
      assert.doesNotMatch(source, /from\s*'@aws-sdk\/(?!client-s3')/, file);
    }
    assert.deepEqual([...imported].sort(), ['GetObjectCommand', 'ListObjectVersionsCommand', 'PutObjectCommand', 'S3Client']);
    assert.doesNotMatch(readFileSync('runner/backup/master-backup-lane.ts', 'utf8'), /@aws-sdk/);
  });

  test('every adapter issues only its own command against the fake client', async () => {
    const names: string[] = [];
    const client = {
      send: async (command: { constructor: { name: string } }) => {
        names.push(command.constructor.name);
        return { Body: bytesOf('x'), VersionId: 'v', IsTruncated: false };
      },
    } as unknown as S3Client;
    await new B2RestoreReader(client, TARGET).listVersions('r2/synthetic-source-test/masters/');
    await new B2RestoreReader(client, TARGET).getVersion('k', 'v');
    await new B2MinimalWriter(client, TARGET).putObject({ key: destinationKeyFor(TARGET, KEY_A), bytes: bytesOf('x'), contentMd5Base64: 'bWQ1', contentType: 'image/png' });
    await new R2MasterSource(client, TARGET).getMaster(KEY_A);
    assert.deepEqual(names, ['ListObjectVersionsCommand', 'GetObjectCommand', 'PutObjectCommand', 'GetObjectCommand']);
  });

  test('the writer refuses a key outside the target masters/ prefix', async () => {
    const client = { send: async () => assert.fail('must not send') } as unknown as S3Client;
    await assert.rejects(new B2MinimalWriter(client, TARGET).putObject({ key: 'r2/synthetic-source-prod/masters/a/b.png', bytes: bytesOf('x'), contentMd5Base64: 'bWQ1', contentType: 'image/png' }), /outside the target/);
  });
});

// ---------------------------------------------------------------------------
// 13. Retries
// ---------------------------------------------------------------------------

describe('S12K-D — 13. retries never intentionally overwrite', () => {
  test('a second full run after success writes nothing', async () => {
    const bytes = bytesOf('once');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes), masterOf(KEY_B, bytesOf('site'))]);
    const b2 = new FakeB2();
    const source = new FakeSource(new Map([[KEY_A, bytes], [KEY_B, bytesOf('site')]]));
    assert.equal((await runLane(ledger, b2, source)).green, true);
    assert.equal(b2.puts.length, 2);
    const again = await runLane(ledger, b2, source, { runId: '9002', runAttempt: '1' });
    assert.equal(again.green, true);
    assert.deepEqual(again.scan.decisions.map((d) => d.scanClass), ['already_verified', 'already_verified']);
    assert.equal(b2.puts.length, 2);
    for (const versions of b2.objects.values()) assert.equal(versions.length, 1);
  });

  test('write succeeded but verify-again never ran → the next scan adopts the exact version, no second PUT', async () => {
    const bytes = bytesOf('interrupted');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const scan = await runVerifyScan({ target: TARGET, ledger, reader: b2 }, RUN);
    const written = await runWriteMissing({ target: TARGET, source: new FakeSource(new Map([[KEY_A, bytes]])), writer: b2 }, scan);
    const next = await runVerifyScan({ target: TARGET, ledger, reader: b2 }, { runId: '9002', runAttempt: '1' });
    assert.equal(next.decisions[0]?.scanClass, 'existing_unproven');
    assert.equal(next.decisions[0]?.evaluation?.outcome, 'verified');
    assert.equal(ledger.rows[0]?.b2VersionId, written.results[0]?.versionId);
    assert.deepEqual(next.candidates, []);
    assert.equal(b2.puts.length, 1);
  });

  test('re-running verify-again is idempotent (no duplicate row)', async () => {
    const bytes = bytesOf('twice');
    const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
    const b2 = new FakeB2();
    const { written } = await runLane(ledger, b2, new FakeSource(new Map([[KEY_A, bytes]])));
    const again = await runVerifyAgain({ target: TARGET, ledger, reader: b2 }, written);
    assert.equal(again.results[0]?.outcome, 'verified');
    assert.equal(again.results[0]?.reason, 'already_recorded');
    assert.equal(ledger.rows.length, 1);
  });

  test('a plan from an earlier run attempt is refused, so "re-run failed jobs" cannot replay PUTs', async () => {
    const ledger = new FakeLedger([masterOf(KEY_A, bytesOf('a'))]);
    const scan = await runVerifyScan({ target: TARGET, ledger, reader: new FakeB2() }, RUN);
    assert.throws(() => parseScanReportForWriter(roundTrip(scan), TARGET, { runId: RUN.runId, runAttempt: '2' }), /another run attempt/);
    assert.throws(() => parseScanReportForWriter(roundTrip(scan), TARGET, { runId: '1', runAttempt: '1' }), /another run/);
  });

  test('a tampered plan (duplicate master, foreign destination key) is refused', async () => {
    const bytes = bytesOf('a');
    const scan = roundTrip(await runVerifyScan({ target: TARGET, ledger: new FakeLedger([masterOf(KEY_A, bytes)]), reader: new FakeB2() }, RUN)) as { candidates: Record<string, unknown>[] };
    const candidate = scan.candidates[0]!;
    assert.throws(() => parseScanReportForWriter({ ...scan, candidates: [candidate, candidate] }, TARGET, RUN), /duplicate master key/);
    assert.throws(() => parseScanReportForWriter({ ...scan, candidates: [{ ...candidate, destinationKey: `r2/synthetic-source-prod/${KEY_A}` }] }, TARGET, RUN), /deterministic key/);
  });

  test('the B2 writer client never retries inside the SDK', async () => {
    const writerClient = createB2WriterClient(TARGET, { accessKeyId: 'id', secretAccessKey: 'secret' });
    assert.equal(await writerClient.config.maxAttempts(), 1);
    const readerClient = createB2Client(TARGET, { accessKeyId: 'id', secretAccessKey: 'secret' });
    assert.equal(await readerClient.config.requestChecksumCalculation(), 'WHEN_REQUIRED');
    assert.equal(await readerClient.config.responseChecksumValidation(), 'WHEN_REQUIRED');
  });
});

// ---------------------------------------------------------------------------
// 14. Credential separation
// ---------------------------------------------------------------------------

describe('S12K-D — 14. credential separation in the entry point', () => {
  test('each CLI mode requires only its own credential family', () => {
    assert.ok(!CREDENTIAL_ENV.write.required.some((n) => /DATABASE|RESTORE/.test(n)));
    assert.ok(!CREDENTIAL_ENV.scan.required.some((n) => /WRITER|R2_|HANDOFF/.test(n)));
    assert.ok(!CREDENTIAL_ENV.verify.required.some((n) => /WRITER|R2_/.test(n)));
    assert.ok(CREDENTIAL_ENV.write.required.includes('FE_HANDOFF_PRIVATE_KEY') && CREDENTIAL_ENV.verify.required.includes('FE_HANDOFF_PRIVATE_KEY'));
    for (const mode of ['scan', 'write', 'verify'] as const) assert.ok(CREDENTIAL_ENV[mode].required.includes('TARGET_CONFIG_JSON'), mode);
  });

  test('the entry point refuses another job\'s credential and names (never echoes) it', () => {
    const verifier = { TARGET_CONFIG_JSON: '{}', BACKUP_VERIFIER_DATABASE_URL: 'postgres://x', B2_RESTORE_KEY_ID: 'r', B2_RESTORE_APPLICATION_KEY: 'rk' };
    const writer = { TARGET_CONFIG_JSON: '{}', R2_SOURCE_ACCESS_KEY_ID: 's', R2_SOURCE_SECRET_ACCESS_KEY: 'ss', B2_WRITER_KEY_ID: 'w', B2_WRITER_APPLICATION_KEY: 'wk-secret-value', FE_HANDOFF_PRIVATE_KEY: 'k' };
    assert.doesNotThrow(() => checkCredentialEnv('scan', verifier));
    assert.doesNotThrow(() => checkCredentialEnv('verify', { ...verifier, FE_HANDOFF_PRIVATE_KEY: 'k' }));
    assert.doesNotThrow(() => checkCredentialEnv('write', writer));
    assert.throws(() => checkCredentialEnv('scan', { ...verifier, B2_WRITER_APPLICATION_KEY: 'wk-secret-value' }), (e: Error) => /must not hold: B2_WRITER_APPLICATION_KEY/.test(e.message) && !e.message.includes('wk-secret-value'));
    assert.throws(() => checkCredentialEnv('scan', { ...verifier, FE_HANDOFF_PRIVATE_KEY: 'k' }), /must not hold: FE_HANDOFF_PRIVATE_KEY/);
    assert.throws(() => checkCredentialEnv('write', { ...writer, BACKUP_VERIFIER_DATABASE_URL: 'postgres://x' }), /must not hold/);
    assert.throws(() => checkCredentialEnv('write', { ...writer, B2_RESTORE_KEY_ID: 'r' }), /must not hold/);
    assert.throws(() => checkCredentialEnv('verify', { ...verifier, FE_HANDOFF_PRIVATE_KEY: 'k', R2_SOURCE_ACCESS_KEY_ID: 's' }), /must not hold/);
    assert.throws(() => checkCredentialEnv('verify', { ...verifier, FE_HANDOFF_PRIVATE_KEY: 'k', CLOUDFLARE_API_TOKEN: 't' }), /must not hold/);
    assert.throws(() => checkCredentialEnv('write', { ...writer, DATABASE_URL: 'postgres://x' }), /must not hold/);
    assert.throws(() => checkCredentialEnv('write', { ...writer, GH_TOKEN: 'g' }), /must not hold/);
    assert.throws(() => checkCredentialEnv('scan', {}), /requires/);
  });
});

// ---------------------------------------------------------------------------
// 15. TEST/PROD isolation (target identifiers only from verified config)
// ---------------------------------------------------------------------------

function syntheticBackupConfig(target: 'test' | 'prod', kind: 'backup-verify' | 'backup-write', salt: string): string {
  const fields: Record<string, string> = kind === 'backup-verify'
    ? { neon_project_id: `synthetic-project-${target}`, neon_branch_id: `br-synthetic-${target}`, neon_database: 'neondb', b2_bucket: `synthetic-backup-${target}`, b2_endpoint: 'https://s3.synthetic-region.example', b2_region: 'synthetic-region', destination_prefix: `r2/synthetic-source-${target}/` }
    : { cloudflare_account_id: '0123456789abcdef0123456789abcdef', r2_source_bucket: `synthetic-source-${target}`, b2_bucket: `synthetic-backup-${target}`, b2_endpoint: 'https://s3.synthetic-region.example', b2_region: 'synthetic-region', destination_prefix: `r2/synthetic-source-${target}/` };
  return JSON.stringify({ schema: 'fe-target-config/1', kind, target, salt: salt.repeat(64).slice(0, 64), ...fields });
}

describe('S12K-D — 15. TEST configuration cannot select a PROD target', () => {
  const forged: BackupTarget[] = [
    { ...TARGET, b2Bucket: 'Not_A_Bucket' },
    { ...TARGET, sourceBucket: 'synthetic-source-prod' },
    { ...TARGET, destinationPrefix: 'r2/synthetic-source-prod/' },
    { ...TARGET, b2Endpoint: 'https://s3.synthetic-region.example/prod' },
    { ...TARGET, name: 'production' as 'prod' },
  ];

  test('the target comes only from a fingerprint-verified config of the workflow\'s own target', () => {
    const testJson = syntheticBackupConfig('test', 'backup-verify', 'a');
    const prodJson = syntheticBackupConfig('prod', 'backup-verify', 'b');
    const empty = { 'backup-verify': null, 'backup-write': null, 'deploy-prepare': null, deploy: null, verify: null, 'control-policy': null };
    const table = {
      test: { ...empty, 'backup-verify': targetConfigFingerprint(parseTargetConfig(testJson, 'backup-verify', 'test')) },
      prod: { ...empty, 'backup-verify': targetConfigFingerprint(parseTargetConfig(prodJson, 'backup-verify', 'prod')) },
    };
    const target = backupTargetFromConfig(verifiedTargetConfig(testJson, 'backup-verify', 'test', table));
    assert.deepEqual({ ...target }, { name: 'test', sourceBucket: 'synthetic-source-test', b2Bucket: 'synthetic-backup-test', destinationPrefix: 'r2/synthetic-source-test/', b2Endpoint: 'https://s3.synthetic-region.example', b2Region: 'synthetic-region' });
    assert.ok(Object.isFrozen(target));
    assert.throws(() => verifiedTargetConfig(testJson, 'backup-verify', 'prod', table), /not a prod config/);
    assert.throws(() => verifiedTargetConfig(prodJson.replace('"prod"', '"test"'), 'backup-verify', 'test', table), /fingerprint mismatch/);
    assert.throws(() => verifiedTargetConfig(testJson, 'backup-verify', 'test', { test: empty, prod: empty }), /no accepted target fingerprint/);
    for (const name of ['PROD', 'production', 'test ', '', 'Test']) assert.throws(() => parseTarget(name), /exactly test or prod/);
  });

  test('a backup-write config cannot name a source bucket other than its destination prefix', () => {
    const json = JSON.parse(syntheticBackupConfig('test', 'backup-write', 'c')) as Record<string, string>;
    assert.throws(() => parseTargetConfig(JSON.stringify({ ...json, r2_source_bucket: 'synthetic-source-prod' }), 'backup-write', 'test'), /destination_prefix must be r2\/<r2_source_bucket>\//);
  });

  test('a forged or inconsistent target is refused by the key mapping, every stage and every adapter', async () => {
    const client = { send: async () => assert.fail('must not send') } as unknown as S3Client;
    const ledger = new FakeLedger([masterOf(KEY_A, bytesOf('a'))]);
    for (const target of forged) {
      assert.throws(() => assertBackupTarget(target), /backup target/);
      assert.throws(() => destinationKeyFor(target, KEY_A), /backup target/);
      assert.throws(() => createB2Client(target, { accessKeyId: 'a', secretAccessKey: 'b' }), /backup target/);
      assert.throws(() => new B2RestoreReader(client, target), /backup target/);
      assert.throws(() => new B2MinimalWriter(client, target), /backup target/);
      assert.throws(() => new R2MasterSource(client, target), /backup target/);
      await assert.rejects(runVerifyScan({ target, ledger, reader: new FakeB2() }, RUN), /backup target/);
      await assert.rejects(runWriteMissing({ target, source: new FakeSource(new Map()), writer: new FakeB2() }, { kind: 's12k-backup-scan', version: 1, target: 'test', run: RUN, decisions: [], candidates: [] }), /backup target/);
      await assert.rejects(runVerifyAgain({ target, ledger, reader: new FakeB2() }, { kind: 's12k-backup-write', version: 1, target: 'test', run: RUN, results: [] }), /backup target/);
    }
  });

  test('the CLI accepts exactly its flags and rejects unknown ones', () => {
    assert.equal(parseBackupCliArgs(['scan', '--target', 'test', '--out', 'o.json']).target, 'test');
    assert.equal(parseBackupCliArgs(['scan', '--target', 'prod', '--out', 'o.json']).target, 'prod');
    assert.throws(() => parseBackupCliArgs(['scan', '--target', 'test', '--out', 'o.json', '--bucket', 'x']), /unknown/);
    assert.throws(() => parseBackupCliArgs(['write', '--target', 'test', '--out', 'o.json']), /--plan is required/);
    assert.throws(() => parseBackupCliArgs(['delete', '--target', 'test']), /expected mode/);
  });
});

// ---------------------------------------------------------------------------
// S12K-D2H — final current-state coverage
// ---------------------------------------------------------------------------

async function greenLane(): Promise<{ ledger: FakeLedger; b2: FakeB2; bytes: Uint8Array; lane: Awaited<ReturnType<typeof runLane>> }> {
  const bytes = bytesOf('covered master');
  const ledger = new FakeLedger([masterOf(KEY_A, bytes)]);
  const b2 = new FakeB2();
  const lane = await runLane(ledger, b2, new FakeSource(new Map([[KEY_A, bytes]])));
  assert.equal(lane.green, true);
  return { ledger, b2, bytes, lane };
}

describe('S12K-D2H — final current-state coverage (read only)', () => {
  test('a fully protected current state is covered and the final lane is green', async () => {
    const { ledger, b2, lane } = await greenLane();
    const coverage = await runFinalCoverage({ target: TARGET, ledger, reader: b2 });
    assert.deepEqual(coverage, { complete: true, failure: null, results: [{ masterKey: KEY_A, covered: true, reason: null, versionId: ledger.rows[0]!.b2VersionId }] });
    assert.equal(finalLaneIsGreen(lane.scanParsed, lane.verify, coverage), true);
  });

  test('G1. an already-verified master whose hash/bytes change after the scan is NOT covered', async () => {
    const { ledger, b2, lane } = await greenLane();
    ledger.masters = [masterOf(KEY_A, bytesOf('changed after scan'))];
    const coverage = await runFinalCoverage({ target: TARGET, ledger, reader: b2 });
    assert.equal(coverage.complete, false);
    assert.equal(coverage.results[0]?.reason, 'verified_proof_conflicts_with_master');
    assert.equal(finalLaneIsGreen(lane.scanParsed, lane.verify, coverage), false);
  });

  test('G2. a new authoritative master that appears after the scan is NOT covered', async () => {
    const { ledger, b2, lane } = await greenLane();
    ledger.masters = [...ledger.masters, masterOf(KEY_B, bytesOf('late arrival'))];
    const coverage = await runFinalCoverage({ target: TARGET, ledger, reader: b2 });
    assert.equal(coverage.complete, false);
    assert.deepEqual(coverage.results.map((r) => [r.masterKey, r.covered, r.reason]), [[KEY_A, true, null], [KEY_B, false, 'missing']]);
    assert.equal(finalLaneIsGreen(lane.scanParsed, lane.verify, coverage), false);
  });

  test('G3. a verified VersionId that disappears from B2 before final coverage is NOT covered', async () => {
    const { ledger, b2, lane } = await greenLane();
    b2.objects.delete(destinationKeyFor(TARGET, KEY_A));
    const coverage = await runFinalCoverage({ target: TARGET, ledger, reader: b2 });
    assert.equal(coverage.results[0]?.reason, 'verified_version_absent_from_b2');
    assert.equal(finalLaneIsGreen(lane.scanParsed, lane.verify, coverage), false);

    const { ledger: ledger2, b2: b22 } = await greenLane();
    b22.deleteMarkers.add(destinationKeyFor(TARGET, KEY_A));
    assert.equal((await runFinalCoverage({ target: TARGET, ledger: ledger2, reader: b22 })).results[0]?.reason, 'delete_marker_present');
  });

  test('G4. a final DB or B2 read failure is NOT green', async () => {
    const { ledger, b2, lane } = await greenLane();
    const failingMasters = Object.assign(Object.create(ledger) as FakeLedger, { listAuthoritativeMasters: async () => { throw new Error('db down'); } });
    const failingBackups = Object.assign(Object.create(ledger) as FakeLedger, { listBackups: async () => { throw new Error('db down'); } });
    const failingList = Object.assign(Object.create(b2) as FakeB2, { listVersions: async () => { throw new Error('503'); } });

    const c1 = await runFinalCoverage({ target: TARGET, ledger: failingMasters, reader: b2 });
    const c2 = await runFinalCoverage({ target: TARGET, ledger, reader: failingList });
    const c3 = await runFinalCoverage({ target: TARGET, ledger: failingBackups, reader: b2 });
    assert.deepEqual([c1.failure, c2.failure, c3.results[0]?.reason], ['ledger_read_failed', 'b2_listing_failed', 'ledger_read_failed']);
    for (const coverage of [c1, c2, c3]) {
      assert.equal(coverage.complete, false);
      assert.equal(finalLaneIsGreen(lane.scanParsed, lane.verify, coverage), false);
    }
  });

  test('G4b. a duplicated authoritative master_key is NOT covered', async () => {
    const { ledger, b2 } = await greenLane();
    ledger.masters = [...ledger.masters, ...ledger.masters];
    const coverage = await runFinalCoverage({ target: TARGET, ledger, reader: b2 });
    assert.deepEqual(coverage.results.map((r) => r.reason), ['duplicate_authoritative_master', 'duplicate_authoritative_master']);
  });

  test('G5. final coverage makes zero INSERTs, zero exact reads, zero writer calls, and never adopts', async () => {
    const { ledger, b2 } = await greenLane();
    const unproven = bytesOf('unproven object');
    ledger.masters = [...ledger.masters, masterOf(KEY_B, unproven)];
    b2.seed(destinationKeyFor(TARGET, KEY_B), unproven);
    const before = { inserts: ledger.inserts.length, rows: ledger.rows.length, puts: b2.puts.length, reads: b2.reads.length };

    const coverage = await runFinalCoverage({ target: TARGET, ledger, reader: b2 });
    assert.equal(coverage.results[1]?.reason, 'existing_unproven');
    assert.deepEqual({ inserts: ledger.inserts.length, rows: ledger.rows.length, puts: b2.puts.length, reads: b2.reads.length }, before);
    // The insert, exact read and writer ports are not even reachable through its parameter types.
    assert.match(readFileSync('runner/backup/master-backup-lane.ts', 'utf8'), /ledger: Pick<BackupLedger, 'listAuthoritativeMasters' \| 'listBackups'>;\n\s+readonly reader: Pick<BackupVersionReader, 'listVersions'>;/);
  });

  test('the verify entry point runs final coverage after verify-again and gates the exit code on it', () => {
    const cli = readFileSync('runner/backup/backup-cli.ts', 'utf8');
    const again = cli.indexOf('await runVerifyAgain(deps, written)');
    const coverage = cli.indexOf('await runFinalCoverage(deps)');
    const verdict = cli.indexOf('const green = finalLaneIsGreen(scan, report, coverage)');
    assert.ok(again > 0 && coverage > again && verdict > coverage);
    assert.match(cli, /return green \? 0 : 1;/);
    assert.doesNotMatch(cli, /laneIsGreen\(scan, report\)/);
  });
});

// ---------------------------------------------------------------------------
// S12K-D2H — strict artifact trust boundary
// ---------------------------------------------------------------------------

type Json = Record<string, unknown> & { decisions: Record<string, unknown>[]; candidates: Record<string, unknown>[] };

/** A real scan with one already_verified (A), one missing (B) and one evaluated existing_unproven (C). */
async function mixedScanJson(): Promise<Json> {
  const KEY_C = 'masters/sample-collection/00000000-0000-4000-8000-0000000000c3.png';
  const a = bytesOf('A'); const b = bytesOf('B'); const c = bytesOf('C');
  const ledger = new FakeLedger([masterOf(KEY_A, a), masterOf(KEY_B, b), masterOf(KEY_C, c)]);
  const b2 = new FakeB2();
  const va = b2.seed(destinationKeyFor(TARGET, KEY_A), a);
  b2.seed(destinationKeyFor(TARGET, 'masters/sample-collection/00000000-0000-4000-8000-0000000000c3.png'), c);
  await ledger.insertBackup({ masterKey: KEY_A, b2VersionId: va, state: 'verified', sourceSha256: sha(a), sourceBytes: 1, observedSha256: sha(a), observedBytes: 1 });
  const scan = roundTrip(await runVerifyScan({ target: TARGET, ledger, reader: b2 }, RUN)) as Json;
  assert.deepEqual(scan.decisions.map((d) => d.scanClass), ['already_verified', 'missing', 'existing_unproven']);
  assert.doesNotThrow(() => parseScanReport(scan, TARGET, RUN));
  return scan;
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

describe('S12K-D2H — strict scan artifact parsing', () => {
  test('G6. a candidate not backed by a missing decision is rejected', async () => {
    const scan = await mixedScanJson();
    const forged = clone(scan);
    forged.candidates.push({ masterKey: KEY_A, destinationKey: destinationKeyFor(TARGET, KEY_A), sourceSha256: sha(bytesOf('A')), sourceBytes: 1 });
    assert.throws(() => parseScanReport(forged, TARGET, RUN), /not backed by exactly one missing decision/);
    assert.throws(() => parseScanReportForWriter(forged, TARGET, RUN), /not backed by exactly one missing decision/);

    const orphan = clone(scan);
    orphan.candidates.push({ masterKey: 'masters/x/y.png', destinationKey: destinationKeyFor(TARGET, 'masters/x/y.png'), sourceSha256: sha(bytesOf('x')), sourceBytes: 1 });
    assert.throws(() => parseScanReport(orphan, TARGET, RUN), /not backed/);
  });

  test('G7. a missing decision without a candidate is rejected', async () => {
    const forged = clone(await mixedScanJson());
    forged.candidates = [];
    assert.throws(() => parseScanReport(forged, TARGET, RUN), /missing decision has no candidate/);
    assert.throws(() => parseScanReportForWriter(forged, TARGET, RUN), /missing decision has no candidate/);
  });

  test('G8. a duplicate scan decision is rejected', async () => {
    const forged = clone(await mixedScanJson());
    forged.decisions.push(clone(forged.decisions[0]!));
    assert.throws(() => parseScanReport(forged, TARGET, RUN), /duplicate master key in decisions/);
  });

  test('G9. malformed or forged evaluations and decisions are rejected field by field', async () => {
    const scan = await mixedScanJson();
    const evaluationAt = scan.decisions.findIndex((d) => d.scanClass === 'existing_unproven');
    const withEvaluation = (patch: Record<string, unknown>): Json => {
      const forged = clone(scan);
      forged.decisions[evaluationAt]!.evaluation = { ...(forged.decisions[evaluationAt]!.evaluation as Record<string, unknown>), ...patch };
      return forged;
    };
    const cases: [Json, RegExp][] = [
      [withEvaluation({ outcome: 'great' }), /evaluation.outcome is invalid/],
      [withEvaluation({ recorded: 'true' }), /recorded is not a boolean/],
      [withEvaluation({ reason: '' }), /evaluation.reason/],
      [withEvaluation({ observedSha256: sha(bytesOf('C')).toUpperCase() }), /observedSha256 is not lowercase/],
      [withEvaluation({ observedBytes: 0 }), /observedBytes is not a positive integer/],
      [withEvaluation({ observedBytes: 1.5 }), /observedBytes is not a positive integer/],
      [withEvaluation({ observedBytes: null }), /not a pair/],
      [withEvaluation({ observedSha256: null, observedBytes: null }), /verified evaluation without an observation/],
    ];
    const decision = (index: number, patch: Record<string, unknown>): Json => {
      const forged = clone(scan);
      Object.assign(forged.decisions[index]!, patch);
      return forged;
    };
    const missingAt = scan.decisions.findIndex((d) => d.scanClass === 'missing');
    cases.push(
      [decision(evaluationAt, { evaluation: null }), /evaluation does not fit existing_unproven/],
      [decision(missingAt, { evaluation: clone(scan.decisions[evaluationAt]!.evaluation) }), /evaluation does not fit missing/],
      [decision(0, { evaluation: 'verified' }), /evaluation is not an object/],
      [decision(0, { scanClass: 'covered' }), /scanClass is invalid/],
      [decision(0, { versionId: null }), /versionId does not fit already_verified/],
      [decision(0, { versionId: '  ' }), /decision.versionId/],
      [decision(missingAt, { versionId: 'v-forged' }), /versionId does not fit missing/],
      [decision(0, { destinationKey: `r2/synthetic-source-prod/${KEY_A}` }), /destinationKey is not the deterministic key/],
      [decision(0, { destinationKey: null }), /destinationKey is not the deterministic key/],
      [decision(0, { masterKey: '../etc/passwd', destinationKey: null }), /invalid master key must be unsafe/],
      [decision(0, { reason: 7 }), /decision.reason/],
    );
    for (const [forged, expected] of cases) assert.throws(() => parseScanReport(forged, TARGET, RUN), expected);
  });

  test('G10. verified + recorded=false can never make the lane green', async () => {
    const scan = await mixedScanJson();
    const forged = clone(scan);
    const at = forged.decisions.findIndex((d) => d.scanClass === 'existing_unproven');
    (forged.decisions[at]!.evaluation as Record<string, unknown>).recorded = false;
    forged.decisions = forged.decisions.filter((d) => d.scanClass !== 'missing');
    forged.candidates = [];
    const parsed = parseScanReport(forged, TARGET, RUN);
    const emptyVerify = { kind: 's12k-backup-verify', version: 1, target: 'test', run: RUN, results: [] } as const;
    assert.equal(laneIsGreen(parsed, emptyVerify), false);

    const honest = parseScanReport({ ...clone(forged), decisions: clone(scan.decisions).filter((d) => d.scanClass !== 'missing') }, TARGET, RUN);
    assert.equal(laneIsGreen(honest, emptyVerify), true);

    const unrecordedAgain = { ...emptyVerify, results: [{ masterKey: KEY_B, destinationKey: destinationKeyFor(TARGET, KEY_B), versionId: 'v', outcome: 'verified' as const, reason: null, recorded: false }] };
    assert.equal(laneIsGreen(honest, unrecordedAgain), false);
  });
});

describe('S12K-D2H — scan/write cross-check in verify mode', () => {
  async function scanAndWrite(): Promise<{ scan: Json; written: Record<string, unknown> & { results: Record<string, unknown>[]; run: Record<string, unknown> } }> {
    const scan = await mixedScanJson();
    const plan = parseScanReportForWriter(scan, TARGET, RUN);
    const written = await runWriteMissing({ target: TARGET, source: new FakeSource(new Map([[KEY_B, bytesOf('B')]])), writer: new FakeB2() }, plan);
    const json = roundTrip(written) as Record<string, unknown> & { results: Record<string, unknown>[]; run: Record<string, unknown> };
    assert.doesNotThrow(() => parseVerifyInputs(scan, json, TARGET, RUN));
    return { scan, written: json };
  }

  test('G11. a write result that was not a scan candidate is rejected', async () => {
    const { scan, written } = await scanAndWrite();
    const forged = clone(written);
    forged.results.push({ ...clone(forged.results[0]!), masterKey: KEY_A, destinationKey: destinationKeyFor(TARGET, KEY_A) });
    assert.throws(() => parseVerifyInputs(scan, forged, TARGET, RUN), /does not match a scan candidate/);
    const dropped = clone(written);
    dropped.results = [];
    assert.throws(() => parseVerifyInputs(scan, dropped, TARGET, RUN), /scan candidate has no write result/);
  });

  test('G12. a scan/write difference in hash, byte count or destination is rejected', async () => {
    const { scan, written } = await scanAndWrite();
    for (const patch of [{ sourceSha256: sha(bytesOf('other')) }, { sourceBytes: 2 }]) {
      const forged = clone(written);
      Object.assign(forged.results[0]!, patch);
      assert.throws(() => parseVerifyInputs(scan, forged, TARGET, RUN), /does not match a scan candidate exactly/);
    }
  });

  test('G13. scan and write from different original run attempts are rejected; a later verify attempt is allowed', async () => {
    const { scan, written } = await scanAndWrite();
    const forged = clone(written);
    forged.run = { runId: RUN.runId, runAttempt: '2' };
    assert.throws(() => parseVerifyInputs(scan, forged, TARGET, RUN), /different run attempts/);
    assert.doesNotThrow(() => parseVerifyInputs(scan, written, TARGET, { runId: RUN.runId, runAttempt: '3' }));
    assert.throws(() => parseVerifyInputs(scan, written, TARGET, { runId: '1', runAttempt: '1' }), /another run/);
    // The writer protection is unchanged: a later attempt cannot reuse this plan.
    assert.throws(() => parseScanReportForWriter(scan, TARGET, { runId: RUN.runId, runAttempt: '2' }), /another run attempt/);
  });

  test('a failed write result must carry a reason and no VersionId; a written one the reverse', async () => {
    const { scan, written } = await scanAndWrite();
    const noReason = clone(written);
    Object.assign(noReason.results[0]!, { status: 'failed', versionId: null, reason: null });
    assert.throws(() => parseVerifyInputs(scan, noReason, TARGET, RUN), /failed result needs a reason/);
    const both = clone(written);
    Object.assign(both.results[0]!, { reason: 'put_failed' });
    assert.throws(() => parseVerifyInputs(scan, both, TARGET, RUN), /written result needs a versionId and no reason/);
  });
});

// ---------------------------------------------------------------------------
// S12K-D2H — R2 endpoint and Action pinning
// ---------------------------------------------------------------------------

describe('S12K-D2H — R2 source endpoint and GitHub Action pinning', () => {
  const ACCOUNT = '0123456789abcdef0123456789abcdef';

  test('G14. R2_SOURCE_ENDPOINT cannot influence the R2 source endpoint', async () => {
    const client = r2SourceClientFor(ACCOUNT, {
      R2_SOURCE_ACCESS_KEY_ID: 'a', R2_SOURCE_SECRET_ACCESS_KEY: 'b',
      R2_SOURCE_ENDPOINT: 'https://attacker.example', R2_S3_ENDPOINT: 'https://attacker.example',
    });
    const endpoint = await client.config.endpoint!();
    assert.deepEqual([endpoint.protocol, endpoint.hostname], ['https:', `${ACCOUNT}.r2.cloudflarestorage.com`]);
    assert.doesNotMatch(readFileSync('runner/backup/backup-cli.ts', 'utf8'), /R2_SOURCE_ENDPOINT|R2_S3_ENDPOINT|endpoint:/);
    assert.doesNotMatch(readFileSync('runner/backup/s3-backup-adapters.ts', 'utf8'), /config\.endpoint|endpoint\?:/);
  });

  test('a malformed Cloudflare account ID fails closed before any client exists', () => {
    for (const accountId of ['', 'attacker.example/x', `${ACCOUNT}.evil`, ACCOUNT.toUpperCase(), ACCOUNT.slice(1)]) {
      assert.throws(() => r2SourceClientFor(accountId, { R2_SOURCE_ACCESS_KEY_ID: 'a', R2_SOURCE_SECRET_ACCESS_KEY: 'b' }), /Cloudflare account ID/);
    }
  });

  test('G15. every GitHub Action in this repository is pinned to a full 40-character commit SHA, never a movable tag', () => {
    let count = 0;
    for (const name of readdirSync('.github/workflows')) {
      const file = `.github/workflows/${name}`;
      for (const match of readFileSync(file, 'utf8').matchAll(/^\s*-?\s*uses:\s*(\S+)(.*)$/gm)) {
        count += 1;
        assert.match(match[1]!, /^actions\/(checkout|setup-node|upload-artifact|download-artifact)@[0-9a-f]{40}$/, `${file}: ${match[1]}`);
        assert.match(match[2]!, /^ # v4\.\d+\.\d+$/, `${file}: ${match[0]}`);
      }
      assert.doesNotMatch(readFileSync(file, 'utf8'), /@v\d|@main|@master|@latest/);
    }
    assert.ok(count >= 12, `${count} pinned uses`);
  });
});
