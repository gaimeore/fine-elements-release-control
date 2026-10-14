/**
 * Deployment orchestration (S12K-E, control-owned; server/ARCHITECTURE.md §8,
 * §19). Frozen semantics, unchanged:
 *
 * - intent lives in the database; a wake-up carries no parameter;
 * - deployment_job is claimed by compare-and-set and its source_commit is
 *   written once, with the claim, from the current release manifest;
 * - duplicate or stale wakes find nothing claimable and are no-ops;
 * - deployment_event stays provider-attempt truth; deployment_control is the
 *   single-flight lock; an indeterminate provider state is never terminalized;
 * - there is no automatic retry and no new attempt: recovery only after an
 *   owner "Check again" (resolve_requested_at) on the exact attempt —
 *   STARTED → recover; one tagged version → adopt; zero tagged versions on two
 *   separated checks → at most ONE same-attempt upload under the one-shot
 *   resume_authorized_at, and only if source_commit still equals the manifest;
 * - verification is read-only toward the provider, never redeploys, and is
 *   monotonic (once verified, Live ✓ is terminal for that attempt);
 * - verification also proves that every rendition the previous succeeded
 *   publication served, and this one no longer has, answers 404 (RC9 PREP-A).
 */
import type { SqlDatabase, SqlExecutor } from '../lib/db.ts';
import { FailClosedError } from '../lib/errors.ts';
import type { ReleaseManifest } from '../lib/manifest.ts';
import { placementsFromSnapshot, removedPlacements, sha256Hex, type RenditionPlacement } from './placements.ts';
import {
  IndeterminateDeploymentError,
  type CurrentPublicDeployment,
  type DeploymentActivationResult,
  type PublicDeploymentProvider,
} from './provider.ts';
import {
  authorizeResume,
  claimControl,
  claimJob,
  ensureControlRow,
  findJob,
  findLatestSucceeded,
  findPublication,
  findStartedEvent,
  findSucceededBefore,
  findTerminalEvent,
  findUnresolvedStartedAttempt,
  hasProviderVersionHistory,
  insertEvent,
  insertVerification,
  listResolvableJobs,
  listUnclaimedJobs,
  listVerifications,
  lockControl,
  releaseControl,
  type DeploymentJob,
} from './repository.ts';

export function correlationTagForAttempt(attemptId: string): string {
  return `fe-${attemptId}`.slice(0, 63);
}

// ---------------------------------------------------------------------------
// Select (deploy-prepare job)
// ---------------------------------------------------------------------------

export type Selection =
  | { readonly mode: 'none'; readonly reason: string }
  | { readonly mode: 'attention'; readonly reason: string }
  | { readonly mode: 'fresh'; readonly job: DeploymentJob }
  | { readonly mode: 'resolve'; readonly job: DeploymentJob };

/** Decides this run's single unit of work from database state only. */
export async function selectWork(db: SqlDatabase, manifest: ReleaseManifest, paused: boolean): Promise<Selection> {
  if (paused) return { mode: 'none', reason: 'paused' };
  const unclaimed = await listUnclaimedJobs(db);
  if (unclaimed.length > 1) return { mode: 'attention', reason: 'multiple_unclaimed_jobs' };
  const candidate = unclaimed[0];
  if (candidate !== undefined) {
    if (await findUnresolvedStartedAttempt(db) !== null) return { mode: 'none', reason: 'pipeline_in_flight' };
    const claimed = await claimJob(db, candidate.attemptId, manifest.source_commit);
    return claimed === null ? { mode: 'none', reason: 'already_claimed' } : { mode: 'fresh', job: claimed };
  }
  const resolvable = await listResolvableJobs(db);
  if (resolvable.length > 1) return { mode: 'attention', reason: 'multiple_resolvable_jobs' };
  const job = resolvable[0];
  if (job === undefined) return { mode: 'none', reason: 'nothing_to_do' };
  if (job.sourceCommit !== manifest.source_commit) return { mode: 'attention', reason: 'source_commit_changed' };
  return { mode: 'resolve', job };
}

// ---------------------------------------------------------------------------
// Deploy (deploy job)
// ---------------------------------------------------------------------------

export interface ClaimRecord {
  readonly attemptId: string;
  readonly publicationId: string;
  readonly claimedAt: string;
  readonly sourceCommit: string;
  readonly mode: 'fresh' | 'resolve';
}

export type DeployOutcome =
  | { readonly status: 'succeeded' | 'failed'; readonly providerVersionId: string }
  | { readonly status: 'started'; readonly providerVersionId: string }
  | { readonly status: 'attention'; readonly reason: string }
  | { readonly status: 'conflict'; readonly reason: string };

export interface DeployDeps {
  readonly db: SqlDatabase;
  readonly provider: PublicDeploymentProvider;
  readonly environment: string;
  /** Uploads the validated, rendition-injected bundle directory. */
  readonly bundleDir: string;
  /** Pause between the two read-only zero-version checks. */
  readonly sleep?: (ms: number) => Promise<void>;
  readonly recheckDelayMs?: number;
}

/** Re-reads the job and refuses anything that is not exactly the claim this run made or resolves. */
async function requireClaim(db: SqlExecutor, claim: ClaimRecord): Promise<DeploymentJob> {
  const job = await findJob(db, claim.attemptId);
  if (job === null) throw new FailClosedError('the claimed deployment job vanished');
  if (job.publicationId !== claim.publicationId || job.sourceCommit !== claim.sourceCommit || job.claimedAt !== claim.claimedAt) {
    throw new FailClosedError('the deployment job is not this run\'s claim');
  }
  return job;
}

export async function runDeploy(deps: DeployDeps, claim: ClaimRecord): Promise<DeployOutcome> {
  const job = await requireClaim(deps.db, claim);
  const tag = correlationTagForAttempt(job.attemptId);
  const started = await findStartedEvent(deps.db, job.attemptId);
  const terminal = await findTerminalEvent(deps.db, job.attemptId);
  if (terminal !== null) return { status: 'attention', reason: 'attempt_already_terminal' };

  if (claim.mode === 'fresh') {
    if (started !== null) return { status: 'attention', reason: 'fresh_attempt_already_started' };
    if (job.resolveRequestedAt !== null || job.resumeAuthorizedAt !== null) return { status: 'attention', reason: 'fresh_attempt_already_resolving' };
    if (await deps.provider.countTaggedVersions(tag) !== 0) return { status: 'attention', reason: 'fresh_attempt_already_uploaded' };
    return await uploadAndComplete(deps, job, tag);
  }

  // resolve: the frozen bounded-recovery table, exact attempt only
  if (job.resolveRequestedAt === null) throw new FailClosedError('recovery requires an owner Check again');
  if (started !== null) return await recoverStarted(deps, job, started.providerVersionId);
  const tagged = await deps.provider.countTaggedVersions(tag);
  if (tagged === 1) {
    const { providerVersionId } = await deps.provider.resolveUploadedVersion(tag);
    return await completeAttempt(deps, job, providerVersionId);
  }
  if (tagged > 1) return { status: 'attention', reason: 'multiple_tagged_versions' };
  if (job.resumeAuthorizedAt !== null) return { status: 'attention', reason: 'resume_already_consumed' };
  await (deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))))(deps.recheckDelayMs ?? 30_000);
  if (await deps.provider.countTaggedVersions(tag) !== 0) return { status: 'attention', reason: 'tagged_version_appeared' };
  const authorized = await authorizeResume(deps.db, job.attemptId);
  if (authorized === null) return { status: 'attention', reason: 'resume_not_authorized' };
  return await uploadAndComplete(deps, authorized, tag);
}

async function uploadAndComplete(deps: DeployDeps, job: DeploymentJob, tag: string): Promise<DeployOutcome> {
  const { providerVersionId } = await deps.provider.uploadVersion(deps.bundleDir, tag);
  return await completeAttempt(deps, job, providerVersionId);
}

async function completeAttempt(deps: DeployDeps, job: DeploymentJob, providerVersionId: string): Promise<DeployOutcome> {
  try {
    await deps.db.withTransaction(async (tx) => {
      await ensureControlRow(tx, deps.environment);
      const control = await lockControl(tx, deps.environment);
      if (control === null) throw new FailClosedError('deployment control row was not created');
      if (control.activeAttemptId !== null || control.acquiredAt !== null) throw new ConflictError('deployment control row is already occupied');
      if (await findUnresolvedStartedAttempt(tx) !== null) throw new ConflictError('an unresolved deployment attempt already exists');
      if (await findStartedEvent(tx, job.attemptId) !== null || await findTerminalEvent(tx, job.attemptId) !== null) {
        throw new ConflictError('deployment attempt already has deployment history');
      }
      if (await hasProviderVersionHistory(tx, providerVersionId)) throw new FailClosedError('provider version already has deployment history');
      if (await claimControl(tx, deps.environment, job.attemptId) !== 1) throw new FailClosedError('deployment control claim did not affect exactly one row');
      await insertEvent(tx, { attemptId: job.attemptId, publicationId: job.publicationId, event: 'started', providerVersionId, detail: null });
    });
  } catch (error) {
    if (error instanceof ConflictError) return { status: 'conflict', reason: error.message };
    throw error;
  }

  let activation: DeploymentActivationResult;
  try {
    activation = await deps.provider.activateVersion(providerVersionId);
  } catch (error) {
    if (error instanceof IndeterminateDeploymentError) return { status: 'started', providerVersionId };
    throw error;
  }
  return await reconcileAndTerminalize(deps, job, providerVersionId, activation);
}

async function recoverStarted(deps: DeployDeps, job: DeploymentJob, providerVersionId: string): Promise<DeployOutcome> {
  await deps.db.withTransaction(async (tx) => {
    const control = await lockControl(tx, deps.environment);
    if (control === null || control.activeAttemptId !== job.attemptId || control.acquiredAt === null) {
      throw new FailClosedError('deployment control row does not own the unresolved attempt');
    }
  });
  return await reconcileAndTerminalize(deps, job, providerVersionId, { outcome: 'accepted' });
}

async function reconcileAndTerminalize(
  deps: DeployDeps,
  job: DeploymentJob,
  providerVersionId: string,
  activation: DeploymentActivationResult,
): Promise<DeployOutcome> {
  const current = await deps.provider.getCurrentDeployment();
  let event: 'succeeded' | 'failed' | null = null;
  let detail: string | null = null;
  if (current !== 'unknown' && isAtFullTraffic(current, providerVersionId)) event = 'succeeded';
  else if (current !== 'unknown' && activation.outcome === 'rejected') { event = 'failed'; detail = activation.detail; }
  if (event === null) return { status: 'started', providerVersionId };

  await deps.db.withTransaction(async (tx) => {
    const started = await findStartedEvent(tx, job.attemptId);
    if (started === null || started.providerVersionId !== providerVersionId || started.publicationId !== job.publicationId) {
      throw new FailClosedError('terminal deployment event does not match its start');
    }
    if (await findTerminalEvent(tx, job.attemptId) !== null) throw new FailClosedError('deployment attempt already has a terminal event');
    await insertEvent(tx, { attemptId: job.attemptId, publicationId: job.publicationId, event, providerVersionId, detail });
    if (await releaseControl(tx, deps.environment, job.attemptId) !== 1) throw new FailClosedError('deployment control release did not affect exactly one row');
  });
  return { status: event, providerVersionId };
}

function isAtFullTraffic(current: CurrentPublicDeployment, providerVersionId: string): boolean {
  return current.versions.some((version) => version.providerVersionId === providerVersionId && version.percentage === 100);
}

class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}

// ---------------------------------------------------------------------------
// Verify (verify job): read-only toward the provider; append-only evidence
// ---------------------------------------------------------------------------

export interface VerifyDeps {
  readonly db: SqlDatabase;
  /** The provider's current deployment (read token only). */
  readonly currentDeployment: () => Promise<CurrentPublicDeployment | 'unknown'>;
  readonly fetch: (url: string) => Promise<{ status: number; contentType: string | null; body: Uint8Array }>;
  readonly origin: string;
  readonly sha256: (bytes: Uint8Array) => string;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly now?: () => number;
  readonly intervalMs?: number;
  readonly windowMs?: number;
  readonly notFoundProbePath: string;
}

export interface VerifyExpectation {
  readonly attemptId: string;
  readonly publicationId: string;
  readonly placements: readonly RenditionPlacement[];
  /** Non-image bundle files whose served bytes must equal the built bundle. */
  readonly files: readonly { readonly path: string; readonly sha256: string }[];
  /** The live publication this attempt replaced, as sealed by select; null when select found none. */
  readonly previousLive: PreviousLiveEvidence | null;
}

/** The previous succeeded attempt's identity and its exact snapshot bytes (read from R2 by select). */
export interface PreviousLiveEvidence {
  readonly attemptId: string;
  readonly publicationId: string;
  readonly providerVersionId: string;
  readonly snapshotSha256: string;
  readonly snapshot: Uint8Array;
}

export type VerifyOutcome = 'verified' | 'unverified' | 'already_verified' | 'not_succeeded';

/**
 * Binds the sealed previous-live evidence to the ledger (the succeeded event
 * immediately before this attempt's, and that publication's content hash)
 * and returns the renditions it served that this publication no longer has.
 * Any doubt about the base is a failure class, never an empty removal set.
 */
export async function removedSincePreviousLive(db: SqlDatabase, expect: VerifyExpectation, terminalEventId: string): Promise<{ failure: string } | { removed: RenditionPlacement[] }> {
  const previous = expect.previousLive;
  const base = await findSucceededBefore(db, terminalEventId);
  if (previous === null || base === null) return { failure: 'previous_live_base_missing' };
  if (base.attemptId !== previous.attemptId || base.publicationId !== previous.publicationId || base.providerVersionId !== previous.providerVersionId) {
    return { failure: 'previous_live_base_mismatch' };
  }
  const publication = await findPublication(db, base.publicationId);
  if (publication === null || publication.contentHash !== previous.snapshotSha256 || sha256Hex(previous.snapshot) !== publication.contentHash) {
    return { failure: 'previous_live_evidence_invalid' };
  }
  try {
    return { removed: removedPlacements(placementsFromSnapshot(previous.snapshot), expect.placements) };
  } catch (error) {
    if (error instanceof FailClosedError) return { failure: 'previous_live_evidence_invalid' };
    throw error;
  }
}

/** One read-only pass; returns null when everything is proven, else the first failure class. */
export async function verifyOnce(deps: VerifyDeps, expect: VerifyExpectation, providerVersionId: string, removed: readonly RenditionPlacement[]): Promise<string | null> {
  const latest = await findLatestSucceeded(deps.db);
  if (latest === null || latest.attemptId !== expect.attemptId) return 'not_latest_succeeded';
  const current = await deps.currentDeployment();
  if (current === 'unknown') return 'provider_unknown';
  if (current.versions.length !== 1 || current.versions[0]!.providerVersionId !== providerVersionId || current.versions[0]!.percentage !== 100) {
    return 'provider_not_single_version';
  }
  for (const placement of expect.placements) {
    const response = await deps.fetch(`${deps.origin}/${placement.publicPath}`);
    if (response.status !== 200 || response.contentType?.split(';')[0]?.trim() !== 'image/webp') return 'image_not_served';
    if (deps.sha256(response.body) !== placement.sha256) return 'image_hash_mismatch';
  }
  for (const file of expect.files) {
    const route = file.path === 'index.html' ? '' : file.path;
    const response = await deps.fetch(`${deps.origin}/${route}`);
    if (response.status !== 200 || deps.sha256(response.body) !== file.sha256) return 'bundle_file_mismatch';
  }
  // Removed content must be absent under the same contract the random probe proves: 404, never old bytes.
  for (const gone of removed) {
    const response = await deps.fetch(`${deps.origin}/${gone.publicPath}`);
    if (deps.sha256(response.body) === gone.sha256) return 'removed_content_still_served';
    if (response.status !== 404) return 'removed_path_not_absent';
  }
  const missing = await deps.fetch(`${deps.origin}/${deps.notFoundProbePath}`);
  if (missing.status !== 404) return 'spa_fallback_answers_missing_file';
  return null;
}

/** Polls about every 15 s for up to 5 min; writes at most one verified row; never redeploys. */
export async function runVerify(deps: VerifyDeps, expect: VerifyExpectation): Promise<VerifyOutcome> {
  const terminal = await findTerminalEvent(deps.db, expect.attemptId);
  if (terminal === null || terminal.event !== 'succeeded' || terminal.publicationId !== expect.publicationId) return 'not_succeeded';
  if ((await listVerifications(deps.db, expect.attemptId)).some((row) => row.outcome === 'verified')) return 'already_verified';
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const deadline = now() + (deps.windowMs ?? 5 * 60_000);
  const base = await removedSincePreviousLive(deps.db, expect, terminal.id);
  let failure: string | null = 'failure' in base ? base.failure : 'not_checked';
  // An untrustworthy base cannot improve by polling: record it at once.
  while ('removed' in base) {
    failure = await verifyOnce(deps, expect, terminal.providerVersionId, base.removed);
    if (failure === null) break;
    if (now() + (deps.intervalMs ?? 15_000) > deadline) break;
    await sleep(deps.intervalMs ?? 15_000);
  }
  await insertVerification(deps.db, {
    publicationId: expect.publicationId,
    attemptId: expect.attemptId,
    outcome: failure === null ? 'verified' : 'unverified',
    failureClass: failure,
  });
  return failure === null ? 'verified' : 'unverified';
}
