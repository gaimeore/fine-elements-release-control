/**
 * Fine Elements — backup lane entry point (one mode per workflow job).
 *
 *   scan   --target <test|prod> --out <scan.fehandoff>
 *   write  --target <test|prod> --plan <scan.fehandoff> --out <write.fehandoff>          (env SCAN_DIGEST)
 *   verify --target <test|prod> --scan-report <scan.fehandoff> --write-report <write.fehandoff> --out <none>
 *                                                                          (env SCAN_DIGEST, WRITE_DIGEST)
 *
 * Before any network call each mode: refuses a foreign credential family;
 * requires the protected production-release run; verifies TARGET_CONFIG_JSON
 * against the committed fingerprint; and (DB modes) verifies the live
 * database identity. Reports cross jobs only as encrypted handoffs bound to
 * this run id and run attempt; digests travel as job outputs. The public log
 * gets fixed status tokens and counts only.
 */
import { pathToFileURL } from 'node:url';

import type { S3Client } from '@aws-sdk/client-s3';

import { assertDatabaseIdentity, createPgDatabase, type SqlDatabase } from '../lib/db.ts';
import { FailClosedError } from '../lib/errors.ts';
import { assertReleaseRun, runContextFrom, setStepOutput, status, type RunContext } from '../lib/github.ts';
import type { HandoffContext } from '../lib/handoff.ts';
import { JOB_ENV, checkJobEnv, requireEnv, type JobKind } from '../lib/job-env.ts';
import { loadRecipientTable, readHandoff, recipientsFor, writeHandoff, type RecipientTable } from '../lib/recipients.ts';
import { loadFingerprintTable, parseTarget, verifiedTargetConfig, type FingerprintTable, type Target } from '../lib/target-config.ts';
import {
  findAuthoritativeMasters,
  insertMasterBackup,
  listAuthoritativeMasters,
  listMasterBackups,
} from './ledger.ts';
import {
  BackupConfigError,
  backupTargetFromConfig,
  finalLaneIsGreen,
  parseScanReportForWriter,
  parseVerifyInputs,
  runFinalCoverage,
  runVerifyAgain,
  runVerifyScan,
  runWriteMissing,
  type BackupLedger,
  type RunIdentity,
} from './master-backup-lane.ts';
import {
  B2MinimalWriter,
  B2RestoreReader,
  R2MasterSource,
  createB2Client,
  createB2WriterClient,
  createR2SourceClient,
} from './s3-backup-adapters.ts';

export type BackupMode = 'scan' | 'write' | 'verify';

const MODE_JOB: Readonly<Record<BackupMode, JobKind>> = { scan: 'backup-scan', write: 'backup-write', verify: 'backup-verify' };

/** The credential split per job: exactly what each mode needs; anything else credential-shaped is refused. */
export const CREDENTIAL_ENV: Readonly<Record<BackupMode, { readonly required: readonly string[] }>> = {
  scan: { required: JOB_ENV['backup-scan'] },
  write: { required: JOB_ENV['backup-write'] },
  verify: { required: JOB_ENV['backup-verify'] },
};

/** Throws naming (never echoing) any missing or foreign variable. */
export function checkCredentialEnv(mode: BackupMode, env: NodeJS.ProcessEnv): void {
  try {
    checkJobEnv(MODE_JOB[mode], env);
  } catch (error) {
    throw new BackupConfigError((error as Error).message.replace(/^backup-(scan|write|verify)/, mode));
  }
}

export interface BackupCliArgs {
  readonly mode: BackupMode;
  readonly target: string;
  readonly out: string;
  readonly plan?: string;
  readonly scanReport?: string;
  readonly writeReport?: string;
}

export function parseBackupCliArgs(args: readonly string[]): BackupCliArgs {
  const mode = args[0];
  if (mode !== 'scan' && mode !== 'write' && mode !== 'verify') {
    throw new BackupConfigError('expected mode: scan, write or verify');
  }
  const flags = new Map<string, string>();
  for (let index = 1; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag === undefined || !['--target', '--out', '--plan', '--scan-report', '--write-report'].includes(flag) || value === undefined || flags.has(flag)) {
      throw new BackupConfigError('unknown, duplicate or incomplete backup argument');
    }
    flags.set(flag, value);
  }
  const allowed: Record<BackupMode, readonly string[]> = {
    scan: ['--target', '--out'],
    write: ['--target', '--out', '--plan'],
    verify: ['--target', '--out', '--scan-report', '--write-report'],
  };
  for (const flag of allowed[mode]) {
    if (!flags.has(flag)) throw new BackupConfigError(`${flag} is required for ${mode}`);
  }
  if (flags.size !== allowed[mode].length) throw new BackupConfigError(`unexpected argument for ${mode}`);
  return {
    mode,
    target: flags.get('--target')!,
    out: flags.get('--out')!,
    plan: flags.get('--plan'),
    scanReport: flags.get('--scan-report'),
    writeReport: flags.get('--write-report'),
  };
}

/** The R2 source client: endpoint derived only from the configured account ID, never from the environment. */
export function r2SourceClientFor(accountId: string, env: NodeJS.ProcessEnv): S3Client {
  return createR2SourceClient({
    accountId,
    credentials: { accessKeyId: env.R2_SOURCE_ACCESS_KEY_ID ?? '', secretAccessKey: env.R2_SOURCE_SECRET_ACCESS_KEY ?? '' },
  });
}

function ledgerOver(db: SqlDatabase): BackupLedger {
  return {
    listAuthoritativeMasters: () => listAuthoritativeMasters(db),
    findAuthoritativeMasters: (masterKey) => findAuthoritativeMasters(db, masterKey),
    listBackups: (masterKey) => listMasterBackups(db, masterKey),
    insertBackup: (row) => insertMasterBackup(db, row),
  };
}

export function handoffContext(run: RunContext, target: Target, producerJob: string, artifact: string): HandoffContext {
  return { repository: run.repository, workflowRef: run.workflowRef, target, runId: run.runId, runAttempt: run.runAttempt, producerJob, artifact };
}

export const SCAN_HANDOFF = { job: 'verify-scan', artifact: 'backup-scan' } as const;
export const WRITE_HANDOFF = { job: 'write-missing', artifact: 'backup-write' } as const;

function countBy<T>(values: readonly T[], key: (value: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    const name = key(value).replace(/[^a-z_]/g, '_');
    counts[name] = (counts[name] ?? 0) + 1;
  }
  return counts;
}

export interface BackupCliTables {
  readonly fingerprints: FingerprintTable;
  readonly recipients: RecipientTable;
}

/** Returns the process exit code. */
export async function runBackupCli(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  tables: BackupCliTables = { fingerprints: loadFingerprintTable(), recipients: loadRecipientTable() },
): Promise<number> {
  const args = parseBackupCliArgs(argv);
  const target = parseTarget(args.target);
  checkCredentialEnv(args.mode, env);
  const run = runContextFrom(env);
  assertReleaseRun(run);
  const identity: RunIdentity = { runId: run.runId, runAttempt: run.runAttempt };

  if (args.mode === 'write') {
    const config = verifiedTargetConfig(env.TARGET_CONFIG_JSON, 'backup-write', target, tables.fingerprints);
    const backupTarget = backupTargetFromConfig(config);
    const outRecipients = recipientsFor(tables.recipients, target, ['backup-verify']);
    const planBytes = readHandoff(args.plan!, env.SCAN_DIGEST, requireEnv(env, 'FE_HANDOFF_PRIVATE_KEY'), handoffContext(run, target, SCAN_HANDOFF.job, SCAN_HANDOFF.artifact));
    const plan = parseScanReportForWriter(JSON.parse(planBytes.toString('utf8')) as unknown, backupTarget, identity);
    const report = await runWriteMissing({
      target: backupTarget,
      source: new R2MasterSource(r2SourceClientFor(config.fields.cloudflare_account_id!, env), backupTarget),
      writer: new B2MinimalWriter(createB2WriterClient(backupTarget, {
        accessKeyId: requireEnv(env, 'B2_WRITER_KEY_ID'),
        secretAccessKey: requireEnv(env, 'B2_WRITER_APPLICATION_KEY'),
      }), backupTarget),
    }, plan);
    const digest = writeHandoff(args.out, Buffer.from(JSON.stringify(report), 'utf8'), outRecipients, handoffContext(run, target, WRITE_HANDOFF.job, WRITE_HANDOFF.artifact));
    setStepOutput(env, 'write_digest', digest);
    // Per-master failures are reported, not fatal: verify-again runs and fails the lane.
    status('FE_BACKUP_WRITE=DONE', countBy(report.results, (r) => r.reason ?? r.status));
    return 0;
  }

  const config = verifiedTargetConfig(env.TARGET_CONFIG_JSON, 'backup-verify', target, tables.fingerprints);
  const backupTarget = backupTargetFromConfig(config);
  const db = createPgDatabase(requireEnv(env, 'BACKUP_VERIFIER_DATABASE_URL'));
  try {
    await assertDatabaseIdentity(db, config);
    const deps = {
      target: backupTarget,
      ledger: ledgerOver(db),
      reader: new B2RestoreReader(createB2Client(backupTarget, {
        accessKeyId: requireEnv(env, 'B2_RESTORE_KEY_ID'),
        secretAccessKey: requireEnv(env, 'B2_RESTORE_APPLICATION_KEY'),
      }), backupTarget),
    };
    if (args.mode === 'scan') {
      const outRecipients = recipientsFor(tables.recipients, target, ['backup-write', 'backup-verify']);
      const report = await runVerifyScan(deps, identity);
      const digest = writeHandoff(args.out, Buffer.from(JSON.stringify(report), 'utf8'), outRecipients, handoffContext(run, target, SCAN_HANDOFF.job, SCAN_HANDOFF.artifact));
      setStepOutput(env, 'scan_digest', digest);
      status('FE_BACKUP_SCAN=DONE', { ...countBy(report.decisions, (d) => d.reason ?? d.scanClass), candidates: report.candidates.length });
      return 0;
    }
    const key = requireEnv(env, 'FE_HANDOFF_PRIVATE_KEY');
    const scanJson = JSON.parse(readHandoff(args.scanReport!, env.SCAN_DIGEST, key, handoffContext(run, target, SCAN_HANDOFF.job, SCAN_HANDOFF.artifact)).toString('utf8')) as unknown;
    const writeJson = JSON.parse(readHandoff(args.writeReport!, env.WRITE_DIGEST, key, handoffContext(run, target, WRITE_HANDOFF.job, WRITE_HANDOFF.artifact)).toString('utf8')) as unknown;
    const { scan, written } = parseVerifyInputs(scanJson, writeJson, backupTarget, identity);
    const report = await runVerifyAgain(deps, written);
    // Final read-only re-check of the CURRENT state, immediately before the verdict.
    const coverage = await runFinalCoverage(deps);
    const green = finalLaneIsGreen(scan, report, coverage);
    status(green ? 'FE_BACKUP_VERIFY=GREEN' : 'FE_BACKUP_VERIFY=RED', {
      ...countBy(report.results, (r) => r.reason ?? r.outcome),
      uncovered: coverage.results.filter((r) => !r.covered).length,
      coverage_failure: coverage.failure === null ? 0 : 1,
    });
    return green ? 0 : 1;
  } finally {
    await db.close();
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runBackupCli(process.argv.slice(2), process.env).then(
    (code) => process.exit(code),
    (error: unknown) => {
      // Only our own refusals are printed; a provider or driver message may name a host or key.
      const refused = error instanceof FailClosedError || error instanceof BackupConfigError;
      console.error(`FE_BACKUP=FAIL ${refused ? `refused: ${(error as Error).message}` : `failed: ${error instanceof Error ? error.name : 'error'}`}`);
      process.exit(1);
    },
  );
}
