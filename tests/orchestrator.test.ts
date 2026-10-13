/**
 * Deployment orchestration against an in-memory database that enforces the
 * frozen 0011/0004–0010 rules the runner relies on (CAS claim, write-once
 * claim/source_commit/resume, single-flight control, append-only monotonic
 * verification) and a fake provider. No real database or provider.
 */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import type { RawRow, SqlDatabase } from '../runner/lib/db.ts';
import type { ReleaseManifest } from '../runner/lib/manifest.ts';
import { correlationTagForAttempt, runDeploy, runVerify, selectWork, type ClaimRecord, type VerifyDeps } from '../runner/deploy/orchestrator.ts';
import { IndeterminateDeploymentError, type CurrentPublicDeployment, type DeploymentActivationResult, type PublicDeploymentProvider } from '../runner/deploy/provider.ts';

const COMMIT = 'a'.repeat(40);
const MANIFEST = { schema: 'fine-elements-release-manifest/1', target: 'test', sequence: 3, source_repository: 'gaimeore/fine-elements', source_commit: COMMIT, source_archive_sha256: 'c'.repeat(64), previous_source_commit: 'b'.repeat(40), migration_ceiling: '0011_x' } as ReleaseManifest;
const A1 = '00000000-0000-4000-8000-0000000000e1';
const A2 = '00000000-0000-4000-8000-0000000000e2';
const P1 = '00000000-0000-4000-8000-0000000000f1';

interface Job { attempt_id: string; publication_id: string; created_at: string; dispatch_accepted_at: string | null; claimed_at: string | null; source_commit: string | null; resolve_requested_at: string | null; resume_authorized_at: string | null }
interface Ev { id: string; attempt_id: string; publication_id: string; event: string; provider_version_id: string; detail: string | null; created_at: string }

class FakeDb implements SqlDatabase {
  jobs: Job[] = [];
  events: Ev[] = [];
  control = new Map<string, { active_attempt_id: string | null; acquired_at: string | null }>();
  verifications: { id: string; publication_id: string; attempt_id: string; outcome: string; failure_class: string | null; observed_at: string }[] = [];
  clock = 0;
  now(): string { this.clock += 1; return new Date(Date.UTC(2026, 9, 14, 0, 0, this.clock)).toISOString(); }

  addJob(attemptId: string, extra: Partial<Job> = {}): void {
    this.jobs.push({ attempt_id: attemptId, publication_id: P1, created_at: this.now(), dispatch_accepted_at: this.now(), claimed_at: null, source_commit: null, resolve_requested_at: null, resume_authorized_at: null, ...extra });
  }

  async query<R extends RawRow = RawRow>(sql: string, params: readonly unknown[] = []): Promise<{ rows: R[]; rowCount: number | null }> {
    const out = (rows: object[]): { rows: R[]; rowCount: number } => ({ rows: rows as R[], rowCount: rows.length });
    const p = params as string[];
    const noTerminal = (a: string): boolean => !this.events.some((e) => e.attempt_id === a && e.event !== 'started');
    if (sql.includes('FROM deployment_job WHERE claimed_at IS NULL')) return out(this.jobs.filter((j) => j.claimed_at === null).slice(0, 2));
    if (sql.includes('j.resolve_requested_at IS NOT NULL')) return out(this.jobs.filter((j) => j.claimed_at !== null && j.resolve_requested_at !== null && noTerminal(j.attempt_id)).slice(0, 2));
    if (sql.startsWith('UPDATE deployment_job SET claimed_at')) {
      const job = this.jobs.find((j) => j.attempt_id === p[0] && j.claimed_at === null);
      if (job === undefined) return out([]);
      job.claimed_at = this.now(); job.source_commit = p[1]!;
      return out([{ ...job }]);
    }
    if (sql.startsWith('UPDATE deployment_job SET resume_authorized_at')) {
      const job = this.jobs.find((j) => j.attempt_id === p[0] && j.resume_authorized_at === null && j.resolve_requested_at !== null && j.claimed_at !== null);
      if (job === undefined) return out([]);
      job.resume_authorized_at = this.now();
      return out([{ ...job }]);
    }
    if (sql.includes('FROM deployment_job WHERE attempt_id = $1')) return out(this.jobs.filter((j) => j.attempt_id === p[0]).map((j) => ({ ...j })));
    if (sql.startsWith('INSERT INTO deployment_event')) {
      const row = { id: p[0]!, attempt_id: p[1]!, publication_id: p[2]!, event: p[3]!, provider_version_id: p[4]!, detail: p[5] ?? null, created_at: this.now() };
      if (row.event === 'started' ? this.events.some((e) => e.attempt_id === row.attempt_id && e.event === 'started') : !noTerminal(row.attempt_id)) throw new Error('unique violation');
      this.events.push(row);
      return out([row]);
    }
    if (sql.includes("WHERE attempt_id = $1 AND event = 'started'")) return out(this.events.filter((e) => e.attempt_id === p[0] && e.event === 'started'));
    if (sql.includes("WHERE attempt_id = $1 AND event <> 'started'")) return out(this.events.filter((e) => e.attempt_id === p[0] && e.event !== 'started'));
    if (sql.includes('FROM deployment_event s')) return out(this.events.filter((e) => e.event === 'started' && noTerminal(e.attempt_id)).slice(0, 2));
    if (sql.includes("WHERE event = 'succeeded' ORDER BY")) return out(this.events.filter((e) => e.event === 'succeeded').slice(-1));
    if (sql.includes('WHERE provider_version_id = $1')) return out(this.events.filter((e) => e.provider_version_id === p[0]));
    if (sql.startsWith('INSERT INTO deployment_control')) { if (!this.control.has(p[0]!)) this.control.set(p[0]!, { active_attempt_id: null, acquired_at: null }); return out([]); }
    if (sql.includes('FROM deployment_control WHERE environment = $1 FOR UPDATE')) { const c = this.control.get(p[0]!); return out(c === undefined ? [] : [{ environment: p[0], ...c }]); }
    if (sql.startsWith('UPDATE deployment_control SET active_attempt_id = $2')) {
      const c = this.control.get(p[0]!);
      if (c === undefined || c.active_attempt_id !== null) return out([]);
      c.active_attempt_id = p[1]!; c.acquired_at = this.now();
      return out([{ environment: p[0] }]);
    }
    if (sql.startsWith('UPDATE deployment_control SET active_attempt_id = NULL')) {
      const c = this.control.get(p[0]!);
      if (c === undefined || c.active_attempt_id !== p[1]) return out([]);
      c.active_attempt_id = null; c.acquired_at = null;
      return out([{ environment: p[0] }]);
    }
    if (sql.includes('FROM publication_verification')) return out(this.verifications.filter((v) => v.attempt_id === p[0]));
    if (sql.startsWith('INSERT INTO publication_verification')) {
      if (this.verifications.some((v) => v.attempt_id === p[2] && v.outcome === 'verified')) throw new Error('publication_verification monotonic guard');
      this.verifications.push({ id: p[0]!, publication_id: p[1]!, attempt_id: p[2]!, outcome: p[3]!, failure_class: p[4] ?? null, observed_at: this.now() });
      return out([]);
    }
    throw new Error(`unexpected SQL: ${sql.slice(0, 80)}`);
  }
  async withTransaction<T>(work: (tx: SqlDatabase) => Promise<T>): Promise<T> { return work(this); }
  async close(): Promise<void> { /* nothing */ }
}

class FakeProvider implements PublicDeploymentProvider {
  versions: { id: string; tag: string }[] = [];
  uploads = 0;
  activations: string[] = [];
  live: string | null = null;
  activation: 'accept' | 'reject' | 'indeterminate' = 'accept';
  async uploadVersion(_dir: string, tag: string): Promise<{ providerVersionId: string }> {
    this.uploads += 1;
    const id = `0000000000000000-${this.uploads}${'0'.repeat(15)}`.slice(0, 33);
    this.versions.push({ id, tag });
    return { providerVersionId: id };
  }
  async resolveUploadedVersion(tag: string): Promise<{ providerVersionId: string }> {
    const matches = this.versions.filter((v) => v.tag === tag);
    if (matches.length !== 1) throw new Error('tag resolution failed closed');
    return { providerVersionId: matches[0]!.id };
  }
  async countTaggedVersions(tag: string): Promise<number> { return this.versions.filter((v) => v.tag === tag).length; }
  async activateVersion(id: string): Promise<DeploymentActivationResult> {
    this.activations.push(id);
    if (this.activation === 'indeterminate') throw new IndeterminateDeploymentError('timeout');
    if (this.activation === 'reject') return { outcome: 'rejected', detail: 'rejected' };
    this.live = id;
    return { outcome: 'accepted' };
  }
  async getCurrentDeployment(): Promise<CurrentPublicDeployment | 'unknown'> {
    return this.live === null ? { versions: [] } : { versions: [{ providerVersionId: this.live, percentage: 100 }] };
  }
}

const deps = (db: FakeDb, provider: FakeProvider) => ({ db, provider, environment: 'test', bundleDir: '/fe/bundle', sleep: async () => undefined, recheckDelayMs: 0 });
const claimOf = (db: FakeDb, attemptId: string, mode: 'fresh' | 'resolve' = 'fresh'): ClaimRecord => {
  const job = db.jobs.find((j) => j.attempt_id === attemptId)!;
  return { attemptId, publicationId: job.publication_id, claimedAt: job.claimed_at!, sourceCommit: job.source_commit!, mode };
};

describe('select / claim', () => {
  test('one unclaimed job is claimed by CAS with the manifest commit; a duplicate wake is a no-op', async () => {
    const db = new FakeDb(); db.addJob(A1);
    const first = await selectWork(db, MANIFEST, false);
    assert.equal(first.mode, 'fresh');
    assert.equal(db.jobs[0]!.source_commit, COMMIT);
    assert.deepEqual(await selectWork(db, MANIFEST, false), { mode: 'none', reason: 'nothing_to_do' });
  });

  test('pause, ambiguity and an in-flight pipeline never claim', async () => {
    const paused = new FakeDb(); paused.addJob(A1);
    assert.deepEqual(await selectWork(paused, MANIFEST, true), { mode: 'none', reason: 'paused' });
    assert.equal(paused.jobs[0]!.claimed_at, null);
    const two = new FakeDb(); two.addJob(A1); two.addJob(A2);
    assert.deepEqual(await selectWork(two, MANIFEST, false), { mode: 'attention', reason: 'multiple_unclaimed_jobs' });
    const busy = new FakeDb(); busy.addJob(A2);
    busy.events.push({ id: 'e', attempt_id: A1, publication_id: P1, event: 'started', provider_version_id: 'v', detail: null, created_at: busy.now() });
    assert.deepEqual(await selectWork(busy, MANIFEST, false), { mode: 'none', reason: 'pipeline_in_flight' });
  });

  test('a resolve request is honoured only while source_commit still equals the manifest', async () => {
    const db = new FakeDb(); db.addJob(A1, { claimed_at: '2026-10-14T00:00:00.000Z', source_commit: COMMIT, resolve_requested_at: '2026-10-14T00:10:00.000Z' });
    assert.equal((await selectWork(db, MANIFEST, false)).mode, 'resolve');
    const moved = new FakeDb(); moved.addJob(A1, { claimed_at: '2026-10-14T00:00:00.000Z', source_commit: 'd'.repeat(40), resolve_requested_at: '2026-10-14T00:10:00.000Z' });
    assert.deepEqual(await selectWork(moved, MANIFEST, false), { mode: 'attention', reason: 'source_commit_changed' });
  });
});

describe('deploy (fresh)', () => {
  test('exactly one tagged upload, STARTED, activation, SUCCEEDED, control released', async () => {
    const db = new FakeDb(); db.addJob(A1); await selectWork(db, MANIFEST, false);
    const provider = new FakeProvider();
    const outcome = await runDeploy(deps(db, provider), claimOf(db, A1));
    assert.equal(outcome.status, 'succeeded');
    assert.equal(provider.uploads, 1);
    assert.equal(provider.versions[0]!.tag, correlationTagForAttempt(A1));
    assert.deepEqual(db.events.map((e) => e.event), ['started', 'succeeded']);
    assert.equal(db.control.get('test')!.active_attempt_id, null);
  });

  test('a claim that is not exactly this run\'s claim is refused before any provider call', async () => {
    const db = new FakeDb(); db.addJob(A1); await selectWork(db, MANIFEST, false);
    const provider = new FakeProvider();
    await assert.rejects(runDeploy(deps(db, provider), { ...claimOf(db, A1), claimedAt: '2026-01-01T00:00:00.000Z' }), /not this run's claim/);
    assert.equal(provider.uploads, 0);
  });

  test('an already-uploaded fresh attempt needs attention, never a second upload', async () => {
    const db = new FakeDb(); db.addJob(A1); await selectWork(db, MANIFEST, false);
    const provider = new FakeProvider(); provider.versions.push({ id: 'existing-version-0001', tag: correlationTagForAttempt(A1) });
    assert.deepEqual(await runDeploy(deps(db, provider), claimOf(db, A1)), { status: 'attention', reason: 'fresh_attempt_already_uploaded' });
    assert.equal(provider.uploads, 0);
  });

  test('an indeterminate activation stays STARTED: never terminalized, never retried', async () => {
    const db = new FakeDb(); db.addJob(A1); await selectWork(db, MANIFEST, false);
    const provider = new FakeProvider(); provider.activation = 'indeterminate';
    assert.equal((await runDeploy(deps(db, provider), claimOf(db, A1))).status, 'started');
    assert.deepEqual(db.events.map((e) => e.event), ['started']);
    assert.equal(provider.uploads, 1);
  });
});

describe('deploy (bounded recovery after an owner Check again)', () => {
  const resolving = (extra: Partial<Job> = {}): FakeDb => {
    const db = new FakeDb();
    db.addJob(A1, { claimed_at: '2026-10-14T00:00:00.000Z', source_commit: COMMIT, resolve_requested_at: '2026-10-14T00:10:00.000Z', ...extra });
    return db;
  };

  test('STARTED without a terminal event → recover that exact attempt; no upload', async () => {
    const db = resolving();
    db.control.set('test', { active_attempt_id: A1, acquired_at: db.now() });
    db.events.push({ id: 'e', attempt_id: A1, publication_id: P1, event: 'started', provider_version_id: 'v-started-0000001', detail: null, created_at: db.now() });
    const provider = new FakeProvider(); provider.live = 'v-started-0000001';
    assert.equal((await runDeploy(deps(db, provider), claimOf(db, A1, 'resolve'))).status, 'succeeded');
    assert.equal(provider.uploads, 0);
  });

  test('one tagged version → adopt; no upload', async () => {
    const db = resolving();
    const provider = new FakeProvider(); provider.versions.push({ id: 'v-tagged-000000001', tag: correlationTagForAttempt(A1) });
    assert.equal((await runDeploy(deps(db, provider), claimOf(db, A1, 'resolve'))).status, 'succeeded');
    assert.equal(provider.uploads, 0);
    assert.deepEqual(provider.activations, ['v-tagged-000000001']);
  });

  test('several tagged versions → attention, no mutation', async () => {
    const db = resolving();
    const provider = new FakeProvider();
    provider.versions.push({ id: 'v1-00000000000001', tag: correlationTagForAttempt(A1) }, { id: 'v2-00000000000002', tag: correlationTagForAttempt(A1) });
    assert.deepEqual(await runDeploy(deps(db, provider), claimOf(db, A1, 'resolve')), { status: 'attention', reason: 'multiple_tagged_versions' });
    assert.equal(db.events.length, 0);
  });

  test('zero tagged versions twice → one-shot resume authority → exactly one upload', async () => {
    const db = resolving();
    const provider = new FakeProvider();
    assert.equal((await runDeploy(deps(db, provider), claimOf(db, A1, 'resolve'))).status, 'succeeded');
    assert.equal(provider.uploads, 1);
    assert.notEqual(db.jobs[0]!.resume_authorized_at, null);
  });

  test('a consumed resume is never granted again', async () => {
    const db = resolving({ resume_authorized_at: '2026-10-14T00:20:00.000Z' });
    const provider = new FakeProvider();
    assert.deepEqual(await runDeploy(deps(db, provider), claimOf(db, A1, 'resolve')), { status: 'attention', reason: 'resume_already_consumed' });
    assert.equal(provider.uploads, 0);
  });

  test('a version appearing between the two checks → attention, no upload', async () => {
    const db = resolving();
    const provider = new FakeProvider();
    const d = { ...deps(db, provider), sleep: async () => { provider.versions.push({ id: 'late-0000000000001', tag: correlationTagForAttempt(A1) }); } };
    assert.deepEqual(await runDeploy(d, claimOf(db, A1, 'resolve')), { status: 'attention', reason: 'tagged_version_appeared' });
    assert.equal(provider.uploads, 0);
    assert.equal(db.jobs[0]!.resume_authorized_at, null);
  });

  test('recovery without a Check again is refused', async () => {
    const db = new FakeDb(); db.addJob(A1, { claimed_at: '2026-10-14T00:00:00.000Z', source_commit: COMMIT });
    await assert.rejects(runDeploy(deps(db, new FakeProvider()), claimOf(db, A1, 'resolve')), /Check again/);
  });
});

describe('verify (read-only, monotonic, never redeploys)', () => {
  const placements = [{ kind: 'collection' as const, publicPath: 'images/collections/sample/x.webp', renditionKey: 'k', sha256: 'h1' }];
  const setup = (): { db: FakeDb; deps: VerifyDeps; served: Map<string, { status: number; type: string; body: string }> } => {
    const db = new FakeDb(); db.addJob(A1);
    db.events.push({ id: 's', attempt_id: A1, publication_id: P1, event: 'started', provider_version_id: 'v-live-0000000001', detail: null, created_at: db.now() });
    db.events.push({ id: 't', attempt_id: A1, publication_id: P1, event: 'succeeded', provider_version_id: 'v-live-0000000001', detail: null, created_at: db.now() });
    const served = new Map([['/images/collections/sample/x.webp', { status: 200, type: 'image/webp', body: 'h1' }], ['/', { status: 200, type: 'text/html', body: 'h2' }]]);
    let clock = 0;
    return { db, served, deps: {
      db,
      currentDeployment: async () => ({ versions: [{ providerVersionId: 'v-live-0000000001', percentage: 100 }] }),
      fetch: async (url) => { const hit = served.get(url.replace('https://synthetic.example', '')); return hit === undefined ? { status: 404, contentType: 'text/html', body: new Uint8Array() } : { status: hit.status, contentType: hit.type, body: new TextEncoder().encode(hit.body) }; },
      origin: 'https://synthetic.example',
      sha256: (bytes) => new TextDecoder().decode(bytes),
      sleep: async () => { clock += 15_000; },
      now: () => clock,
      notFoundProbePath: '__probe',
    } };
  };
  const expect = { attemptId: A1, publicationId: P1, placements, files: [{ path: 'index.html', sha256: 'h2' }] };

  test('proven live → exactly one verified row; a second run is a no-op', async () => {
    const { db, deps: d } = setup();
    assert.equal(await runVerify(d, expect), 'verified');
    assert.equal(await runVerify(d, expect), 'already_verified');
    assert.deepEqual(db.verifications.map((v) => v.outcome), ['verified']);
  });

  test('a mismatch until the window closes → one unverified row with its failure class', async () => {
    const { db, deps: d, served } = setup();
    served.set('/images/collections/sample/x.webp', { status: 200, type: 'image/webp', body: 'other' });
    assert.equal(await runVerify(d, expect), 'unverified');
    assert.deepEqual(db.verifications.map((v) => [v.outcome, v.failure_class]), [['unverified', 'image_hash_mismatch']]);
  });

  test('an SPA fallback answering a missing file with 200 is not live', async () => {
    const { db, deps: d, served } = setup();
    served.set('/__probe', { status: 200, type: 'text/html', body: 'shell' });
    assert.equal(await runVerify(d, expect), 'unverified');
    assert.equal(db.verifications[0]!.failure_class, 'spa_fallback_answers_missing_file');
  });

  test('nothing is verified unless the attempt SUCCEEDED; verify holds no upload capability', async () => {
    const { db, deps: d } = setup();
    db.events = db.events.filter((e) => e.event === 'started');
    assert.equal(await runVerify(d, expect), 'not_succeeded');
    assert.equal(db.verifications.length, 0);
    assert.ok(!('uploadVersion' in d) && !('provider' in d));
  });
});
