/**
 * Deployment persistence for the control-plane runner. Mirrors the private
 * repository's schema authority exactly (migrations 0004–0011; 0011 is
 * frozen): deployment_job (orchestration identity), deployment_event
 * (provider-attempt truth), deployment_control (single flight) and
 * publication_verification (append-only, monotonic). No new column, table
 * or grant is required: the deploy_runner role already holds every
 * statement used here.
 */
import { randomUUID } from 'node:crypto';

import {
  readEnum,
  readNullableString,
  readNullableTimestamp,
  readString,
  readTimestamp,
  type RawRow,
  type SqlExecutor,
} from '../lib/db.ts';

export interface DeploymentJob {
  readonly attemptId: string;
  readonly publicationId: string;
  readonly createdAt: string;
  readonly dispatchAcceptedAt: string | null;
  readonly claimedAt: string | null;
  readonly sourceCommit: string | null;
  readonly resolveRequestedAt: string | null;
  readonly resumeAuthorizedAt: string | null;
}

export type DeploymentEventKind = 'started' | 'succeeded' | 'failed';
const EVENT_KINDS: readonly DeploymentEventKind[] = ['started', 'succeeded', 'failed'];

export interface DeploymentEvent {
  readonly id: string;
  readonly attemptId: string;
  readonly publicationId: string;
  readonly event: DeploymentEventKind;
  readonly providerVersionId: string;
  readonly detail: string | null;
  readonly createdAt: string;
}

export interface PublicationRef {
  readonly id: string;
  readonly contentHash: string;
  readonly snapshotKey: string;
}

export type VerificationOutcome = 'verified' | 'unverified';

export interface PublicationVerification {
  readonly id: string;
  readonly publicationId: string;
  readonly attemptId: string;
  readonly outcome: VerificationOutcome;
  readonly failureClass: string | null;
}

const JOB_COLUMNS = 'attempt_id, publication_id, created_at, dispatch_accepted_at, claimed_at, source_commit, resolve_requested_at, resume_authorized_at';
const EVENT_COLUMNS = 'id, attempt_id, publication_id, event, provider_version_id, detail, created_at';

function mapJob(row: RawRow): DeploymentJob {
  return {
    attemptId: readString(row, 'attempt_id'),
    publicationId: readString(row, 'publication_id'),
    createdAt: readTimestamp(row, 'created_at'),
    dispatchAcceptedAt: readNullableTimestamp(row, 'dispatch_accepted_at'),
    claimedAt: readNullableTimestamp(row, 'claimed_at'),
    sourceCommit: readNullableString(row, 'source_commit'),
    resolveRequestedAt: readNullableTimestamp(row, 'resolve_requested_at'),
    resumeAuthorizedAt: readNullableTimestamp(row, 'resume_authorized_at'),
  };
}

function mapEvent(row: RawRow): DeploymentEvent {
  return {
    id: readString(row, 'id'),
    attemptId: readString(row, 'attempt_id'),
    publicationId: readString(row, 'publication_id'),
    event: readEnum(row, 'event', EVENT_KINDS),
    providerVersionId: readString(row, 'provider_version_id'),
    detail: readNullableString(row, 'detail'),
    createdAt: readTimestamp(row, 'created_at'),
  };
}

// --- deployment_job ---------------------------------------------------------

/** Unclaimed jobs, oldest first; at most 2 so ambiguity is visible. */
export async function listUnclaimedJobs(db: SqlExecutor): Promise<DeploymentJob[]> {
  const result = await db.query(`SELECT ${JOB_COLUMNS} FROM deployment_job WHERE claimed_at IS NULL ORDER BY created_at, attempt_id LIMIT 2`);
  return result.rows.map(mapJob);
}

/** Claimed jobs with an owner "Check again" and no terminal event; at most 2. */
export async function listResolvableJobs(db: SqlExecutor): Promise<DeploymentJob[]> {
  const result = await db.query(
    `SELECT ${JOB_COLUMNS} FROM deployment_job j
     WHERE j.claimed_at IS NOT NULL AND j.resolve_requested_at IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM deployment_event e WHERE e.attempt_id = j.attempt_id AND e.event <> 'started')
     ORDER BY j.created_at, j.attempt_id LIMIT 2`,
  );
  return result.rows.map(mapJob);
}

export async function findJob(db: SqlExecutor, attemptId: string): Promise<DeploymentJob | null> {
  const result = await db.query(`SELECT ${JOB_COLUMNS} FROM deployment_job WHERE attempt_id = $1`, [attemptId]);
  const row = result.rows[0];
  return row === undefined ? null : mapJob(row);
}

/** Compare-and-set claim; source_commit is written once, with the claim. null = someone else claimed. */
export async function claimJob(db: SqlExecutor, attemptId: string, sourceCommit: string): Promise<DeploymentJob | null> {
  const result = await db.query(
    `UPDATE deployment_job SET claimed_at = CURRENT_TIMESTAMP, source_commit = $2
     WHERE attempt_id = $1 AND claimed_at IS NULL
     RETURNING ${JOB_COLUMNS}`,
    [attemptId, sourceCommit],
  );
  const row = result.rows[0];
  return row === undefined ? null : mapJob(row);
}

/** One-shot resume authority (compare-and-set); the database refuses to move it once set. */
export async function authorizeResume(db: SqlExecutor, attemptId: string): Promise<DeploymentJob | null> {
  const result = await db.query(
    `UPDATE deployment_job SET resume_authorized_at = CURRENT_TIMESTAMP
     WHERE attempt_id = $1 AND resume_authorized_at IS NULL AND resolve_requested_at IS NOT NULL AND claimed_at IS NOT NULL
     RETURNING ${JOB_COLUMNS}`,
    [attemptId],
  );
  const row = result.rows[0];
  return row === undefined ? null : mapJob(row);
}

// --- publication ------------------------------------------------------------

export async function findPublication(db: SqlExecutor, publicationId: string): Promise<PublicationRef | null> {
  const result = await db.query('SELECT id, content_hash, snapshot_key FROM publication WHERE id = $1', [publicationId]);
  const row = result.rows[0];
  return row === undefined ? null : { id: readString(row, 'id'), contentHash: readString(row, 'content_hash'), snapshotKey: readString(row, 'snapshot_key') };
}

// --- deployment_event / deployment_control ----------------------------------

export async function insertEvent(db: SqlExecutor, event: Omit<DeploymentEvent, 'id' | 'createdAt'>): Promise<DeploymentEvent> {
  const result = await db.query(
    `INSERT INTO deployment_event (id, attempt_id, publication_id, event, provider_version_id, detail)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING ${EVENT_COLUMNS}`,
    [randomUUID(), event.attemptId, event.publicationId, event.event, event.providerVersionId, event.detail],
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('insertEvent: INSERT ... RETURNING produced no row');
  return mapEvent(row);
}

export async function findStartedEvent(db: SqlExecutor, attemptId: string): Promise<DeploymentEvent | null> {
  const result = await db.query(`SELECT ${EVENT_COLUMNS} FROM deployment_event WHERE attempt_id = $1 AND event = 'started'`, [attemptId]);
  const row = result.rows[0];
  return row === undefined ? null : mapEvent(row);
}

export async function findTerminalEvent(db: SqlExecutor, attemptId: string): Promise<DeploymentEvent | null> {
  const result = await db.query(`SELECT ${EVENT_COLUMNS} FROM deployment_event WHERE attempt_id = $1 AND event <> 'started'`, [attemptId]);
  const row = result.rows[0];
  return row === undefined ? null : mapEvent(row);
}

export async function findUnresolvedStartedAttempt(db: SqlExecutor): Promise<DeploymentEvent | null> {
  const result = await db.query(
    `SELECT ${EVENT_COLUMNS} FROM deployment_event s
     WHERE s.event = 'started'
       AND NOT EXISTS (SELECT 1 FROM deployment_event t WHERE t.attempt_id = s.attempt_id AND t.event <> 'started')
     LIMIT 2`,
  );
  if (result.rows.length > 1) throw new Error('multiple unresolved attempts found');
  const row = result.rows[0];
  return row === undefined ? null : mapEvent(row);
}

export async function findLatestSucceeded(db: SqlExecutor): Promise<DeploymentEvent | null> {
  const result = await db.query(`SELECT ${EVENT_COLUMNS} FROM deployment_event WHERE event = 'succeeded' ORDER BY created_at DESC, id DESC LIMIT 1`);
  const row = result.rows[0];
  return row === undefined ? null : mapEvent(row);
}

/** The succeeded event immediately before the given event, in findLatestSucceeded's sequence. */
export async function findSucceededBefore(db: SqlExecutor, eventId: string): Promise<DeploymentEvent | null> {
  const result = await db.query(
    `SELECT e.id, e.attempt_id, e.publication_id, e.event, e.provider_version_id, e.detail, e.created_at
     FROM deployment_event e JOIN deployment_event cur ON cur.id = $1
     WHERE e.event = 'succeeded' AND (e.created_at, e.id) < (cur.created_at, cur.id)
     ORDER BY e.created_at DESC, e.id DESC LIMIT 1`,
    [eventId],
  );
  const row = result.rows[0];
  return row === undefined ? null : mapEvent(row);
}

export async function hasProviderVersionHistory(db: SqlExecutor, providerVersionId: string): Promise<boolean> {
  const result = await db.query('SELECT id FROM deployment_event WHERE provider_version_id = $1 LIMIT 1', [providerVersionId]);
  return result.rows.length > 0;
}

export async function ensureControlRow(db: SqlExecutor, environment: string): Promise<void> {
  await db.query('INSERT INTO deployment_control (environment, active_attempt_id, acquired_at) VALUES ($1, NULL, NULL) ON CONFLICT (environment) DO NOTHING', [environment]);
}

export async function lockControl(db: SqlExecutor, environment: string): Promise<{ activeAttemptId: string | null; acquiredAt: string | null } | null> {
  const result = await db.query('SELECT environment, active_attempt_id, acquired_at FROM deployment_control WHERE environment = $1 FOR UPDATE', [environment]);
  const row = result.rows[0];
  return row === undefined ? null : { activeAttemptId: readNullableString(row, 'active_attempt_id'), acquiredAt: readNullableTimestamp(row, 'acquired_at') };
}

export async function claimControl(db: SqlExecutor, environment: string, attemptId: string): Promise<number> {
  const result = await db.query(
    `UPDATE deployment_control SET active_attempt_id = $2, acquired_at = CURRENT_TIMESTAMP
     WHERE environment = $1 AND active_attempt_id IS NULL AND acquired_at IS NULL RETURNING environment`,
    [environment, attemptId],
  );
  return result.rowCount ?? result.rows.length;
}

export async function releaseControl(db: SqlExecutor, environment: string, attemptId: string): Promise<number> {
  const result = await db.query(
    `UPDATE deployment_control SET active_attempt_id = NULL, acquired_at = NULL
     WHERE environment = $1 AND active_attempt_id = $2 AND acquired_at IS NOT NULL RETURNING environment`,
    [environment, attemptId],
  );
  return result.rowCount ?? result.rows.length;
}

// --- publication_verification ----------------------------------------------

export async function listVerifications(db: SqlExecutor, attemptId: string): Promise<PublicationVerification[]> {
  const result = await db.query(
    'SELECT id, publication_id, attempt_id, outcome, failure_class FROM publication_verification WHERE attempt_id = $1 ORDER BY observed_at, id',
    [attemptId],
  );
  return result.rows.map((row) => ({
    id: readString(row, 'id'),
    publicationId: readString(row, 'publication_id'),
    attemptId: readString(row, 'attempt_id'),
    outcome: readEnum(row, 'outcome', ['verified', 'unverified'] as const),
    failureClass: readNullableString(row, 'failure_class'),
  }));
}

/** Append-only; the database refuses anything after an attempt's verified row. Runs under READ COMMITTED. */
export async function insertVerification(db: SqlExecutor, verification: Omit<PublicationVerification, 'id'>): Promise<void> {
  await db.query(
    'INSERT INTO publication_verification (id, publication_id, attempt_id, outcome, failure_class) VALUES ($1, $2, $3, $4, $5)',
    [randomUUID(), verification.publicationId, verification.attemptId, verification.outcome, verification.failureClass],
  );
}
