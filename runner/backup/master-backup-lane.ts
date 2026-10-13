/**
 * Fine Elements — automated master backup lane (core). Relocated from the
 * private source repository (S12K-D2, accepted at c6daad9) as backup Model C:
 * this public control repository is now the one backup authority.
 *
 * ARCHITECTURE.md §19: verify-scan → write-missing → verify-again. Each job
 * holds a different credential set, so each stage is a separate function
 * over narrow ports and the stages hand over plain JSON reports.
 *
 * INVARIANT. A master is VERIFIED only after one exact, immutable B2
 * VersionId has been read back and its observed SHA-256 and byte count equal
 * the authoritative master's content_hash and master_bytes. master_backup
 * stays append-only (migration 0011); this module only INSERTs.
 *
 * FAIL CLOSED. Anything that is not provably "missing" never reaches the
 * writer. A mismatch is history, never an overwrite request. The writer
 * issues a single PutObject per proven-missing master and nothing else.
 *
 * No I/O here beyond the injected ports; the S3 adapters live in
 * ./s3-backup-adapters.ts and the env wiring in ./backup-cli.ts. Target
 * identifiers come only from the fingerprint-verified TARGET_CONFIG_JSON.
 */

import { createHash } from 'node:crypto';

import type { Target, TargetConfig } from '../lib/target-config.ts';
import {
  deriveMasterBackupProof,
  type AuthoritativeMaster,
  type MasterBackupRecord,
  type NewMasterBackup,
} from './ledger.ts';

const sha256Hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

export class BackupConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BackupConfigError';
  }
}

// ---------------------------------------------------------------------------
// Target and destination key
// ---------------------------------------------------------------------------

export interface BackupTarget {
  readonly name: Target;
  /** The R2 bucket the masters are read from (derived from destinationPrefix). */
  readonly sourceBucket: string;
  readonly b2Bucket: string;
  /** `r2/<sourceBucket>/` — the one naming convention. */
  readonly destinationPrefix: string;
  readonly b2Endpoint: string;
  readonly b2Region: string;
}

const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

/**
 * The backup target of a fingerprint-verified backup-verify or backup-write
 * config. The source bucket is never configured separately from the
 * destination prefix, so the two can never disagree.
 */
export function backupTargetFromConfig(config: TargetConfig): BackupTarget {
  if (config.kind !== 'backup-verify' && config.kind !== 'backup-write') {
    throw new BackupConfigError('a backup target needs a backup-verify or backup-write config');
  }
  const prefix = config.fields.destination_prefix ?? '';
  const target: BackupTarget = Object.freeze({
    name: config.target,
    sourceBucket: prefix.slice(3, -1),
    b2Bucket: config.fields.b2_bucket ?? '',
    destinationPrefix: prefix,
    b2Endpoint: config.fields.b2_endpoint ?? '',
    b2Region: config.fields.b2_region ?? '',
  });
  if (config.kind === 'backup-write' && config.fields.r2_source_bucket !== target.sourceBucket) {
    throw new BackupConfigError('backup-write r2_source_bucket must equal the destination prefix bucket');
  }
  return assertBackupTarget(target);
}

/** Refuses any structurally inconsistent target. */
export function assertBackupTarget(target: BackupTarget): BackupTarget {
  if (target.name !== 'test' && target.name !== 'prod') throw new BackupConfigError('backup target name must be test or prod');
  if (!BUCKET.test(target.sourceBucket) || !BUCKET.test(target.b2Bucket)) throw new BackupConfigError('backup target bucket is malformed');
  if (target.destinationPrefix !== `r2/${target.sourceBucket}/`) throw new BackupConfigError('backup target destination prefix must be r2/<source bucket>/');
  if (!/^https:\/\/[a-z0-9.-]+$/.test(target.b2Endpoint) || !/^[a-z0-9-]{2,40}$/.test(target.b2Region)) {
    throw new BackupConfigError('backup target endpoint or region is malformed');
  }
  return target;
}

// masters/{collectionId}/{photographId}.{ext} or masters/site/{siteImageId}.{ext}
const MASTER_KEY_PATTERN = /^masters\/(?:[A-Za-z0-9][A-Za-z0-9._-]*\/)+[A-Za-z0-9][A-Za-z0-9._-]*$/;

export function isValidMasterKey(masterKey: string): boolean {
  return MASTER_KEY_PATTERN.test(masterKey);
}

/** The deterministic B2 key: `r2/<R2 bucket>/<R2 master key>`. */
export function destinationKeyFor(target: BackupTarget, masterKey: string): string {
  assertBackupTarget(target);
  if (!isValidMasterKey(masterKey)) {
    throw new BackupConfigError('master key is not a valid masters/ key');
  }
  return `${target.destinationPrefix}${masterKey}`;
}

/** The B2 prefix every key of the target lives under (the key restriction). */
export function mastersPrefixFor(target: BackupTarget): string {
  return `${assertBackupTarget(target).destinationPrefix}masters/`;
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

export interface B2VersionEntry {
  readonly key: string;
  readonly versionId: string;
  readonly kind: 'version' | 'delete_marker';
}

export interface ObservedVersion {
  readonly bytes: Uint8Array;
  /** The VersionId the response reported, or null when it reported none. */
  readonly versionId: string | null;
}

/** The independent B2 restore reader (listFiles + readFiles). */
export interface BackupVersionReader {
  listVersions(prefix: string): Promise<readonly B2VersionEntry[]>;
  /** null ONLY when B2 definitively reports that exact version absent. */
  getVersion(key: string, versionId: string): Promise<ObservedVersion | null>;
}

/** The minimal B2 writer (writeFiles). */
export interface BackupObjectWriter {
  putObject(input: {
    readonly key: string;
    readonly bytes: Uint8Array;
    readonly contentMd5Base64: string;
    readonly contentType: string;
  }): Promise<{ readonly versionId: string | null }>;
}

/** The R2 read-only source. */
export interface MasterSourceReader {
  getMaster(masterKey: string): Promise<{ readonly bytes: Uint8Array; readonly contentType: string | null } | null>;
}

/** The backup-verifier DB credential: master identity SELECT, master_backup SELECT/INSERT. */
export interface BackupLedger {
  listAuthoritativeMasters(): Promise<readonly AuthoritativeMaster[]>;
  findAuthoritativeMasters(masterKey: string): Promise<readonly AuthoritativeMaster[]>;
  listBackups(masterKey: string): Promise<readonly MasterBackupRecord[]>;
  insertBackup(row: NewMasterBackup): Promise<MasterBackupRecord>;
}

export interface RunIdentity {
  readonly runId: string;
  readonly runAttempt: string;
}

// ---------------------------------------------------------------------------
// Classification (pure)
// ---------------------------------------------------------------------------

export type ScanClass = 'already_verified' | 'missing' | 'existing_unproven' | 'unsafe' | 'indeterminate';

export interface ScanClassification {
  readonly scanClass: ScanClass;
  readonly reason: string | null;
  /** The exact version the class refers to (verified proof or the lone unproven version). */
  readonly versionId: string | null;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

function isValidAuthoritativeMaster(master: AuthoritativeMaster): boolean {
  return isValidMasterKey(master.masterKey)
    && SHA256_HEX.test(master.contentHash)
    && Number.isSafeInteger(master.masterBytes)
    && master.masterBytes > 0;
}

/**
 * Classifies one authoritative master from its ledger rows and the B2
 * entries at its exact destination key. Fails closed: every shape that is
 * not one of the three proven states is unsafe.
 */
export function classifyMaster(
  master: AuthoritativeMaster,
  backups: readonly MasterBackupRecord[],
  entriesAtKey: readonly B2VersionEntry[],
): ScanClassification {
  const unsafe = (reason: string): ScanClassification => ({ scanClass: 'unsafe', reason, versionId: null });

  if (!isValidAuthoritativeMaster(master)) return unsafe('invalid_authoritative_master');
  if (backups.some((row) => row.masterKey !== master.masterKey)) return unsafe('ledger_rows_for_other_master');
  if (entriesAtKey.some((entry) => entry.kind === 'delete_marker')) return unsafe('delete_marker_present');

  const versions = entriesAtKey.filter((entry) => entry.kind === 'version');
  const verified = backups.filter((row) => row.state === 'verified');
  if (verified.length > 1) return unsafe('multiple_verified_proofs');

  const proofRow = verified[0];
  if (proofRow !== undefined) {
    if (deriveMasterBackupProof(proofRow, master) === null) return unsafe('verified_proof_conflicts_with_master');
    if (!versions.some((entry) => entry.versionId === proofRow.b2VersionId)) {
      return unsafe('verified_version_absent_from_b2');
    }
    // A later B2 version never invalidates an earlier proof (§19).
    return { scanClass: 'already_verified', reason: null, versionId: proofRow.b2VersionId };
  }

  if (backups.length > 0) return unsafe('mismatch_recorded');

  const [only, ...others] = versions;
  if (only === undefined) return { scanClass: 'missing', reason: null, versionId: null };
  if (others.length > 0) return unsafe('multiple_versions_without_proof');
  return { scanClass: 'existing_unproven', reason: null, versionId: only.versionId };
}

// ---------------------------------------------------------------------------
// Exact-version evaluation (shared by verify-scan and verify-again)
// ---------------------------------------------------------------------------

export type EvaluationOutcome = 'verified' | 'mismatch' | 'unsafe' | 'indeterminate';

export interface Evaluation {
  readonly outcome: EvaluationOutcome;
  readonly reason: string | null;
  readonly observedSha256: string | null;
  readonly observedBytes: number | null;
  /** True only when the outcome was INSERTed into master_backup. */
  readonly recorded: boolean;
}

function notRecorded(outcome: EvaluationOutcome, reason: string): Evaluation {
  return { outcome, reason, observedSha256: null, observedBytes: null, recorded: false };
}

/**
 * Reads the exact (key, versionId), compares it with the authoritative
 * master, and appends the observation. Never reads "latest", never by key
 * alone. A transient read failure records nothing, so the next run
 * re-evaluates the same version.
 */
export async function evaluateExactVersion(
  ledger: BackupLedger,
  reader: BackupVersionReader,
  master: AuthoritativeMaster,
  destinationKey: string,
  versionId: string,
): Promise<Evaluation> {
  if (versionId.trim() === '') return notRecorded('unsafe', 'blank_version_id');

  let observed: ObservedVersion | null;
  try {
    observed = await reader.getVersion(destinationKey, versionId);
  } catch {
    return notRecorded('indeterminate', 'exact_version_read_failed');
  }
  if (observed !== null && observed.versionId !== null && observed.versionId !== versionId) {
    return notRecorded('unsafe', 'version_id_echo_mismatch');
  }

  // An empty or absent object cannot be recorded as an observation
  // (observed_bytes > 0), so it is a mismatch that "could not be observed".
  const observation = observed === null || observed.bytes.byteLength === 0
    ? null
    : { sha256: sha256Hex(observed.bytes), bytes: observed.bytes.byteLength };
  const verified = observation !== null
    && observation.sha256 === master.contentHash
    && observation.bytes === master.masterBytes;

  const row: NewMasterBackup = {
    masterKey: master.masterKey,
    b2VersionId: versionId,
    state: verified ? 'verified' : 'mismatch',
    sourceSha256: master.contentHash,
    sourceBytes: master.masterBytes,
    observedSha256: observation?.sha256 ?? null,
    observedBytes: observation?.bytes ?? null,
  };
  const reason = verified ? null : observation === null ? 'exact_version_not_observable' : 'observed_differs_from_source';
  try {
    await ledger.insertBackup(row);
  } catch {
    return { outcome: 'indeterminate', reason: 'ledger_insert_failed', observedSha256: row.observedSha256, observedBytes: row.observedBytes, recorded: false };
  }
  return { outcome: row.state, reason, observedSha256: row.observedSha256, observedBytes: row.observedBytes, recorded: true };
}

// ---------------------------------------------------------------------------
// verify-scan
// ---------------------------------------------------------------------------

export interface WriteCandidate {
  readonly masterKey: string;
  readonly destinationKey: string;
  readonly sourceSha256: string;
  readonly sourceBytes: number;
}

export interface ScanDecision extends ScanClassification {
  readonly masterKey: string;
  readonly destinationKey: string | null;
  /** Only for existing_unproven: the exact-version evaluation verify-scan ran. */
  readonly evaluation: Evaluation | null;
}

export interface ScanReport {
  readonly kind: 's12k-backup-scan';
  readonly version: 1;
  readonly target: BackupTarget['name'];
  readonly run: RunIdentity;
  readonly decisions: readonly ScanDecision[];
  /** The writer's whole input: only masters proven missing. */
  readonly candidates: readonly WriteCandidate[];
}

export async function runVerifyScan(
  deps: { readonly target: BackupTarget; readonly ledger: BackupLedger; readonly reader: BackupVersionReader },
  run: RunIdentity,
): Promise<ScanReport> {
  const target = assertBackupTarget(deps.target);
  const masters = await deps.ledger.listAuthoritativeMasters();

  let entries: readonly B2VersionEntry[] | null;
  try {
    entries = await deps.reader.listVersions(mastersPrefixFor(target));
  } catch {
    entries = null;
  }

  const keyCounts = new Map<string, number>();
  for (const master of masters) keyCounts.set(master.masterKey, (keyCounts.get(master.masterKey) ?? 0) + 1);

  const decisions: ScanDecision[] = [];
  const candidates: WriteCandidate[] = [];
  for (const master of masters) {
    const destinationKey = isValidMasterKey(master.masterKey) ? destinationKeyFor(target, master.masterKey) : null;
    const decide = (classification: ScanClassification, evaluation: Evaluation | null = null): void => {
      decisions.push({ masterKey: master.masterKey, destinationKey, ...classification, evaluation });
    };

    if (destinationKey === null) { decide({ scanClass: 'unsafe', reason: 'invalid_master_key', versionId: null }); continue; }
    if ((keyCounts.get(master.masterKey) ?? 0) > 1) { decide({ scanClass: 'unsafe', reason: 'duplicate_authoritative_master', versionId: null }); continue; }
    if (entries === null) { decide({ scanClass: 'indeterminate', reason: 'b2_listing_failed', versionId: null }); continue; }

    let backups: readonly MasterBackupRecord[];
    try {
      backups = await deps.ledger.listBackups(master.masterKey);
    } catch {
      decide({ scanClass: 'indeterminate', reason: 'ledger_read_failed', versionId: null });
      continue;
    }

    const classification = classifyMaster(master, backups, entries.filter((entry) => entry.key === destinationKey));
    if (classification.scanClass === 'missing') {
      candidates.push({ masterKey: master.masterKey, destinationKey, sourceSha256: master.contentHash, sourceBytes: master.masterBytes });
      decide(classification);
    } else if (classification.scanClass === 'existing_unproven' && classification.versionId !== null) {
      // §19: verify-scan reads the exact version it evaluates and records it.
      decide(classification, await evaluateExactVersion(deps.ledger, deps.reader, master, destinationKey, classification.versionId));
    } else {
      decide(classification);
    }
  }

  return { kind: 's12k-backup-scan', version: 1, target: target.name, run, decisions, candidates };
}

// ---------------------------------------------------------------------------
// write-missing
// ---------------------------------------------------------------------------

export interface WriteResult extends WriteCandidate {
  readonly status: 'written' | 'failed';
  /** The exact VersionId PutObject returned; null unless written. */
  readonly versionId: string | null;
  readonly reason: string | null;
}

export interface WriteReport {
  readonly kind: 's12k-backup-write';
  readonly version: 1;
  readonly target: BackupTarget['name'];
  readonly run: RunIdentity;
  readonly results: readonly WriteResult[];
}

/**
 * At most one PutObject per proven-missing candidate. No read-before-write is
 * possible with the writer's capabilities, so retries are made safe upstream:
 * the plan must come from THIS run attempt's verify-scan (parseScanReportForWriter),
 * and a re-run re-scans first.
 */
export async function runWriteMissing(
  deps: { readonly target: BackupTarget; readonly source: MasterSourceReader; readonly writer: BackupObjectWriter },
  plan: ScanReport,
): Promise<WriteReport> {
  const target = assertBackupTarget(deps.target);
  const results: WriteResult[] = [];
  for (const candidate of plan.candidates) {
    const fail = (reason: string): void => { results.push({ ...candidate, status: 'failed', versionId: null, reason }); };

    let source: Awaited<ReturnType<MasterSourceReader['getMaster']>>;
    try {
      source = await deps.source.getMaster(candidate.masterKey);
    } catch {
      fail('source_read_failed');
      continue;
    }
    if (source === null) { fail('source_missing'); continue; }
    if (source.bytes.byteLength !== candidate.sourceBytes || sha256Hex(source.bytes) !== candidate.sourceSha256) {
      fail('source_changed');
      continue;
    }

    let versionId: string | null;
    try {
      ({ versionId } = await deps.writer.putObject({
        key: destinationKeyFor(target, candidate.masterKey),
        bytes: source.bytes,
        contentMd5Base64: createHash('md5').update(source.bytes).digest('base64'),
        contentType: source.contentType?.trim() || 'application/octet-stream',
      }));
    } catch {
      // Unknown whether B2 stored it; the next verify-scan decides. Never re-PUT here.
      fail('put_failed');
      continue;
    }
    if (versionId === null || versionId.trim() === '') { fail('put_without_version_id'); continue; }
    results.push({ ...candidate, status: 'written', versionId, reason: null });
  }
  return { kind: 's12k-backup-write', version: 1, target: target.name, run: plan.run, results };
}

// ---------------------------------------------------------------------------
// verify-again
// ---------------------------------------------------------------------------

export interface VerifyResult {
  readonly masterKey: string;
  readonly destinationKey: string;
  readonly versionId: string | null;
  readonly outcome: EvaluationOutcome | 'not_written';
  readonly reason: string | null;
  readonly recorded: boolean;
}

export interface VerifyReport {
  readonly kind: 's12k-backup-verify';
  readonly version: 1;
  readonly target: BackupTarget['name'];
  readonly run: RunIdentity;
  readonly results: readonly VerifyResult[];
}

export async function runVerifyAgain(
  deps: { readonly target: BackupTarget; readonly ledger: BackupLedger; readonly reader: BackupVersionReader },
  written: WriteReport,
): Promise<VerifyReport> {
  const target = assertBackupTarget(deps.target);
  const results: VerifyResult[] = [];
  for (const result of written.results) {
    const base = { masterKey: result.masterKey, destinationKey: result.destinationKey, versionId: result.versionId };
    const conclude = (outcome: VerifyResult['outcome'], reason: string | null, recorded = false): void => {
      results.push({ ...base, outcome, reason, recorded });
    };

    if (result.status !== 'written' || result.versionId === null || result.versionId.trim() === '') {
      conclude('not_written', result.reason ?? 'put_without_version_id');
      continue;
    }
    const versionId = result.versionId;

    try {
      const masters = await deps.ledger.findAuthoritativeMasters(result.masterKey);
      const master = masters[0];
      if (masters.length !== 1 || master === undefined) { conclude('unsafe', 'authoritative_master_not_unique'); continue; }
      if (master.contentHash !== result.sourceSha256 || master.masterBytes !== result.sourceBytes) {
        conclude('unsafe', 'source_changed');
        continue;
      }

      const backups = await deps.ledger.listBackups(master.masterKey);
      const sameVersion = backups.find((row) => row.b2VersionId === versionId);
      if (sameVersion !== undefined) {
        // Idempotent re-run of this job: the observation is already appended.
        conclude(deriveMasterBackupProof(sameVersion, master) !== null ? 'verified' : 'mismatch', 'already_recorded', true);
        continue;
      }
      if (backups.length > 0) { conclude('unsafe', 'ledger_proof_conflict'); continue; }

      const entries = (await deps.reader.listVersions(result.destinationKey)).filter((entry) => entry.key === result.destinationKey);
      if (entries.some((entry) => entry.kind === 'delete_marker')) { conclude('unsafe', 'delete_marker_present'); continue; }
      if (entries.some((entry) => entry.versionId !== versionId)) { conclude('unsafe', 'conflicting_version_present'); continue; }

      const evaluation = await evaluateExactVersion(deps.ledger, deps.reader, master, destinationKeyFor(target, master.masterKey), versionId);
      conclude(evaluation.outcome, evaluation.reason, evaluation.recorded);
    } catch {
      conclude('indeterminate', 'verify_again_read_failed');
    }
  }
  return { kind: 's12k-backup-verify', version: 1, target: target.name, run: written.run, results };
}

/** The scan/write/verify run is green only when every scanned master ends verified AND recorded. */
export function laneIsGreen(scan: ScanReport, verify: VerifyReport): boolean {
  const provedAgain = (r: VerifyResult): boolean => r.outcome === 'verified' && r.recorded;
  const verifiedAgain = new Set(verify.results.filter(provedAgain).map((r) => r.masterKey));
  return verify.results.every(provedAgain)
    && scan.decisions.every((d) =>
      d.scanClass === 'already_verified'
      || (d.scanClass === 'existing_unproven' && isRecordedVerifiedProof(d.evaluation))
      || (d.scanClass === 'missing' && verifiedAgain.has(d.masterKey)));
}

function isRecordedVerifiedProof(evaluation: Evaluation | null): boolean {
  return evaluation !== null
    && evaluation.outcome === 'verified'
    && evaluation.recorded
    && evaluation.observedSha256 !== null
    && evaluation.observedBytes !== null;
}

// ---------------------------------------------------------------------------
// Final current-state coverage (read only)
// ---------------------------------------------------------------------------

export interface CoverageResult {
  readonly masterKey: string;
  readonly covered: boolean;
  readonly reason: string | null;
  /** The exact verified VersionId that covers the master, when covered. */
  readonly versionId: string | null;
}

export interface CoverageReport {
  readonly complete: boolean;
  /** Set when the coverage could not be read at all. */
  readonly failure: string | null;
  readonly results: readonly CoverageResult[];
}

/**
 * Re-reads the CURRENT authoritative masters, master_backup rows and B2
 * listing after verify-again, independently of the earlier scan. Read only
 * by type: it is handed no insert, no exact-version read and no writer, so it
 * can never record, adopt or write. A master is covered only when its exact
 * verified proof matches the current master and that version is still in B2.
 */
export async function runFinalCoverage(deps: {
  readonly target: BackupTarget;
  readonly ledger: Pick<BackupLedger, 'listAuthoritativeMasters' | 'listBackups'>;
  readonly reader: Pick<BackupVersionReader, 'listVersions'>;
}): Promise<CoverageReport> {
  const target = assertBackupTarget(deps.target);
  const incomplete = (failure: string): CoverageReport => ({ complete: false, failure, results: [] });

  let masters: readonly AuthoritativeMaster[];
  let entries: readonly B2VersionEntry[];
  try {
    masters = await deps.ledger.listAuthoritativeMasters();
  } catch {
    return incomplete('ledger_read_failed');
  }
  try {
    entries = await deps.reader.listVersions(mastersPrefixFor(target));
  } catch {
    return incomplete('b2_listing_failed');
  }

  const keyCounts = new Map<string, number>();
  for (const master of masters) keyCounts.set(master.masterKey, (keyCounts.get(master.masterKey) ?? 0) + 1);

  const results: CoverageResult[] = [];
  for (const master of masters) {
    const uncovered = (reason: string): void => { results.push({ masterKey: master.masterKey, covered: false, reason, versionId: null }); };
    if ((keyCounts.get(master.masterKey) ?? 0) !== 1) { uncovered('duplicate_authoritative_master'); continue; }
    if (!isValidMasterKey(master.masterKey)) { uncovered('invalid_master_key'); continue; }

    let backups: readonly MasterBackupRecord[];
    try {
      backups = await deps.ledger.listBackups(master.masterKey);
    } catch {
      uncovered('ledger_read_failed');
      continue;
    }
    const destinationKey = destinationKeyFor(target, master.masterKey);
    const classification = classifyMaster(master, backups, entries.filter((entry) => entry.key === destinationKey));
    if (classification.scanClass === 'already_verified') {
      results.push({ masterKey: master.masterKey, covered: true, reason: null, versionId: classification.versionId });
    } else {
      // missing / existing_unproven are left for the NEXT fresh run's verify-scan.
      uncovered(classification.reason ?? classification.scanClass);
    }
  }
  return { complete: results.every((r) => r.covered), failure: null, results };
}

/** The workflow may report green only when the run AND the final coverage are green. */
export function finalLaneIsGreen(scan: ScanReport, verify: VerifyReport, coverage: CoverageReport): boolean {
  return laneIsGreen(scan, verify) && coverage.failure === null && coverage.complete;
}

// ---------------------------------------------------------------------------
// Report parsing (trust boundary: job artifacts)
// ---------------------------------------------------------------------------

function fail(message: string): never {
  throw new BackupConfigError(`invalid backup report: ${message}`);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} is not an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() === '') fail(`${label} is not a non-blank string`);
  return value;
}

function nullableText(value: unknown, label: string): string | null {
  return value === null ? null : text(value, label);
}

function array(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) fail(`${label} is not an array`);
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) fail(`${label} is invalid`);
  return value as T;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) fail(`${label} is not a positive integer`);
  return value;
}

function sha256(value: unknown, label: string): string {
  if (typeof value !== 'string' || !SHA256_HEX.test(value)) fail(`${label} is not lowercase SHA-256 hex`);
  return value;
}

function parseCandidate(value: unknown, target: BackupTarget): WriteCandidate {
  const raw = record(value, 'candidate');
  const masterKey = text(raw.masterKey, 'candidate.masterKey');
  const destinationKey = text(raw.destinationKey, 'candidate.destinationKey');
  if (!isValidMasterKey(masterKey) || destinationKey !== destinationKeyFor(target, masterKey)) {
    fail('candidate.destinationKey is not the deterministic key');
  }
  return {
    masterKey,
    destinationKey,
    sourceSha256: sha256(raw.sourceSha256, 'candidate.sourceSha256'),
    sourceBytes: positiveInteger(raw.sourceBytes, 'candidate.sourceBytes'),
  };
}

const EVALUATION_OUTCOMES: readonly EvaluationOutcome[] = ['verified', 'mismatch', 'unsafe', 'indeterminate'];

/** Field by field; never a cast. */
function parseEvaluation(value: unknown): Evaluation {
  const raw = record(value, 'evaluation');
  const outcome = oneOf(raw.outcome, EVALUATION_OUTCOMES, 'evaluation.outcome');
  if (typeof raw.recorded !== 'boolean') fail('evaluation.recorded is not a boolean');
  const reason = nullableText(raw.reason, 'evaluation.reason');
  const observedSha256 = raw.observedSha256 === null ? null : sha256(raw.observedSha256, 'evaluation.observedSha256');
  const observedBytes = raw.observedBytes === null ? null : positiveInteger(raw.observedBytes, 'evaluation.observedBytes');
  if ((observedSha256 === null) !== (observedBytes === null)) fail('evaluation observed SHA-256 and bytes are not a pair');
  if (outcome === 'verified' && (observedSha256 === null || reason !== null)) fail('verified evaluation without an observation');
  return { outcome, reason, observedSha256, observedBytes, recorded: raw.recorded };
}

const SCAN_CLASSES: readonly ScanClass[] = ['already_verified', 'missing', 'existing_unproven', 'unsafe', 'indeterminate'];

function parseDecision(value: unknown, target: BackupTarget): ScanDecision {
  const raw = record(value, 'decision');
  const masterKey = text(raw.masterKey, 'decision.masterKey');
  const scanClass = oneOf(raw.scanClass, SCAN_CLASSES, 'decision.scanClass');
  const reason = nullableText(raw.reason, 'decision.reason');
  const versionId = nullableText(raw.versionId, 'decision.versionId');
  const destinationKey = nullableText(raw.destinationKey, 'decision.destinationKey');

  if (isValidMasterKey(masterKey)) {
    if (destinationKey !== destinationKeyFor(target, masterKey)) fail('decision.destinationKey is not the deterministic key');
  } else if (destinationKey !== null || scanClass !== 'unsafe') {
    fail('a decision for an invalid master key must be unsafe without a destination');
  }

  const versionRequired = scanClass === 'already_verified' || scanClass === 'existing_unproven';
  if (versionRequired !== (versionId !== null)) fail(`decision.versionId does not fit ${scanClass}`);

  const evaluation = raw.evaluation === null ? null : parseEvaluation(raw.evaluation);
  if ((scanClass === 'existing_unproven') !== (evaluation !== null)) fail(`decision.evaluation does not fit ${scanClass}`);

  return { masterKey, destinationKey, scanClass, reason, versionId, evaluation };
}

function parseRun(value: unknown): RunIdentity {
  const raw = record(value, 'run');
  return { runId: text(raw.runId, 'run.runId'), runAttempt: text(raw.runAttempt, 'run.runAttempt') };
}

function parseEnvelope(json: unknown, kind: string, target: BackupTarget): Record<string, unknown> {
  const raw = record(json, 'report');
  if (raw.kind !== kind || raw.version !== 1) fail(`expected ${kind} version 1`);
  if (raw.target !== assertBackupTarget(target).name) fail('report target differs');
  return raw;
}

function uniqueByMasterKey<T extends { readonly masterKey: string }>(values: readonly T[], label: string): readonly T[] {
  if (new Set(values.map((value) => value.masterKey)).size !== values.length) fail(`duplicate master key in ${label}`);
  return values;
}

/**
 * The whole scan artifact, structurally checked: unique decisions, and the
 * candidates are exactly the missing decisions (same master, same key).
 */
export function parseScanReport(json: unknown, target: BackupTarget, run: RunIdentity): ScanReport {
  const raw = parseEnvelope(json, 's12k-backup-scan', target);
  const scanRun = parseRun(raw.run);
  if (scanRun.runId !== run.runId) fail('scan report belongs to another run');
  const decisions = uniqueByMasterKey(array(raw.decisions, 'decisions').map((value) => parseDecision(value, target)), 'decisions');
  const candidates = uniqueByMasterKey(array(raw.candidates, 'candidates').map((value) => parseCandidate(value, target)), 'candidates');

  const missing = new Map(decisions.filter((d) => d.scanClass === 'missing').map((d) => [d.masterKey, d]));
  for (const candidate of candidates) {
    const decision = missing.get(candidate.masterKey);
    if (decision === undefined || decision.destinationKey !== candidate.destinationKey) {
      fail('candidate is not backed by exactly one missing decision');
    }
  }
  if (missing.size !== candidates.length) fail('a missing decision has no candidate');

  return { kind: 's12k-backup-scan', version: 1, target: target.name, run: scanRun, decisions, candidates };
}

/**
 * The writer's plan: the strictly parsed scan from THIS run attempt. A plan
 * from an earlier attempt is refused, so "re-run failed jobs" can never
 * replay PUTs; a fresh run re-proves "missing" first.
 */
export function parseScanReportForWriter(json: unknown, target: BackupTarget, run: RunIdentity): ScanReport {
  const scan = parseScanReport(json, target, run);
  if (scan.run.runAttempt !== run.runAttempt) {
    fail('plan belongs to another run attempt; start a fresh run so verify-scan re-proves missing');
  }
  return scan;
}

/** verify-again input. Same run id; a later attempt may re-verify idempotently. */
export function parseWriteReport(json: unknown, target: BackupTarget, run: RunIdentity): WriteReport {
  const raw = parseEnvelope(json, 's12k-backup-write', target);
  const writeRun = parseRun(raw.run);
  if (writeRun.runId !== run.runId) fail('write report belongs to another run');
  const results = uniqueByMasterKey(array(raw.results, 'results').map((value): WriteResult => {
    const entry = record(value, 'result');
    const candidate = parseCandidate(entry, target);
    const status = oneOf(entry.status, ['written', 'failed'] as const, 'result.status');
    const versionId = nullableText(entry.versionId, 'result.versionId');
    const reason = nullableText(entry.reason, 'result.reason');
    if (status === 'written' && (versionId === null || reason !== null)) fail('a written result needs a versionId and no reason');
    if (status === 'failed' && (versionId !== null || reason === null)) fail('a failed result needs a reason and no versionId');
    return { ...candidate, status, versionId, reason };
  }), 'results');
  return { kind: 's12k-backup-write', version: 1, target: target.name, run: writeRun, results };
}

/**
 * verify-again's inputs, cross-checked: both artifacts come from the same
 * original run attempt, and the write results are exactly the scan's
 * candidates with identical identity fields.
 */
export function parseVerifyInputs(
  scanJson: unknown,
  writeJson: unknown,
  target: BackupTarget,
  run: RunIdentity,
): { readonly scan: ScanReport; readonly written: WriteReport } {
  const scan = parseScanReport(scanJson, target, run);
  const written = parseWriteReport(writeJson, target, run);
  if (scan.target !== written.target) fail('scan and write targets differ');
  if (scan.run.runId !== written.run.runId || scan.run.runAttempt !== written.run.runAttempt) {
    fail('scan and write reports come from different run attempts');
  }
  const candidates = new Map(scan.candidates.map((c) => [c.masterKey, c]));
  for (const result of written.results) {
    const candidate = candidates.get(result.masterKey);
    if (
      candidate === undefined
      || candidate.destinationKey !== result.destinationKey
      || candidate.sourceSha256 !== result.sourceSha256
      || candidate.sourceBytes !== result.sourceBytes
    ) {
      fail('write result does not match a scan candidate exactly');
    }
  }
  if (written.results.length !== scan.candidates.length) fail('a scan candidate has no write result');
  return { scan, written };
}
