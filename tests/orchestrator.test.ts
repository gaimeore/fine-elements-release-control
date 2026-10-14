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
import { parsePreviousLive } from '../runner/deploy/deploy-cli.ts';
import { correlationTagForAttempt, removedSincePreviousLive, runDeploy, runVerify, selectWork, type ClaimRecord, type VerifyDeps, type VerifyExpectation } from '../runner/deploy/orchestrator.ts';
import { placementsFromSnapshot, removedPlacements, sha256Hex, type RenditionPlacement } from '../runner/deploy/placements.ts';
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
  publications = new Map<string, { id: string; content_hash: string; snapshot_key: string }>();
  /** Every write statement, by its leading words: verification must only ever append its own row. */
  writes: string[] = [];
  clock = 0;
  now(): string { this.clock += 1; return new Date(Date.UTC(2026, 9, 14, 0, 0, this.clock)).toISOString(); }

  addJob(attemptId: string, extra: Partial<Job> = {}): void {
    this.jobs.push({ attempt_id: attemptId, publication_id: P1, created_at: this.now(), dispatch_accepted_at: this.now(), claimed_at: null, source_commit: null, resolve_requested_at: null, resume_authorized_at: null, ...extra });
  }

  async query<R extends RawRow = RawRow>(sql: string, params: readonly unknown[] = []): Promise<{ rows: R[]; rowCount: number | null }> {
    const out = (rows: object[]): { rows: R[]; rowCount: number } => ({ rows: rows as R[], rowCount: rows.length });
    const p = params as string[];
    const noTerminal = (a: string): boolean => !this.events.some((e) => e.attempt_id === a && e.event !== 'started');
    if (/^(INSERT|UPDATE|DELETE)\b/.test(sql)) this.writes.push(sql.split(/\s+/).slice(0, 3).join(' '));
    if (sql.includes('JOIN deployment_event cur ON cur.id = $1')) {
      const cur = this.events.find((e) => e.id === p[0]);
      const key = (e: Ev): string => `${e.created_at} ${e.id}`;
      if (cur === undefined) return out([]);
      return out(this.events.filter((e) => e.event === 'succeeded' && key(e) < key(cur)).sort((a, b) => (key(a) < key(b) ? -1 : 1)).slice(-1));
    }
    if (sql.includes('FROM publication WHERE id = $1')) { const pub = this.publications.get(p[0]!); return out(pub === undefined ? [] : [pub]); }
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

// --- removed-content absence (S12K RC9 PREP-A) ------------------------------

const A0 = '00000000-0000-4000-8000-0000000000e0';
const P0 = '00000000-0000-4000-8000-0000000000f0';
const PREV_VERSION = 'v-prev-0000000001';
const LIVE_VERSION = 'v-live-0000000001';
const idOf = (n: number): string => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
/** A rendition filename `<id>-<64 hex>.webp`; the hash character makes a replacement visible. */
const file = (n: number, hash: string): string => `${idOf(n)}-${hash.repeat(64)}.webp`;

type Entry = string | { readonly file: string; readonly [key: string]: unknown };
function snapshotOf(collections: Record<string, readonly Entry[]>, portrait?: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    schemaVersion: 2,
    collections: Object.fromEntries(Object.entries(collections).map(([key, entries]) => [key, entries.map((e) => (typeof e === 'string' ? { file: e } : e))])),
    homepage: portrait === undefined ? {} : { aboutPortrait: { file: portrait } },
  }));
}

/** A0/P0 (snapshot `previous`) was live before A1/P1 succeeded; P1 serves exactly `next`. */
function scenario(previous: Uint8Array, next: readonly RenditionPlacement[]) {
  const db = new FakeDb(); db.addJob(A0, { publication_id: P0 }); db.addJob(A1);
  const hash = sha256Hex(previous);
  db.publications.set(P0, { id: P0, content_hash: hash, snapshot_key: `snapshots/${hash}.json` });
  db.events.push({ id: 's0', attempt_id: A0, publication_id: P0, event: 'started', provider_version_id: PREV_VERSION, detail: null, created_at: db.now() });
  db.events.push({ id: 't0', attempt_id: A0, publication_id: P0, event: 'succeeded', provider_version_id: PREV_VERSION, detail: null, created_at: db.now() });
  db.events.push({ id: 's', attempt_id: A1, publication_id: P1, event: 'started', provider_version_id: LIVE_VERSION, detail: null, created_at: db.now() });
  db.events.push({ id: 't', attempt_id: A1, publication_id: P1, event: 'succeeded', provider_version_id: LIVE_VERSION, detail: null, created_at: db.now() });
  const served = new Map<string, { status: number; type: string; body: string }>([['/', { status: 200, type: 'text/html', body: 'h2' }]]);
  for (const placement of next) served.set(`/${placement.publicPath}`, { status: 200, type: 'image/webp', body: placement.sha256 });
  const fetched: string[] = [];
  const provider = new FakeProvider(); provider.live = LIVE_VERSION;
  let clock = 0;
  let sleeps = 0;
  const deps: VerifyDeps = {
    db,
    currentDeployment: () => provider.getCurrentDeployment(),
    fetch: async (url) => {
      const route = url.replace('https://synthetic.example', '');
      fetched.push(route);
      const hit = served.get(route);
      return hit === undefined ? { status: 404, contentType: 'text/html', body: new TextEncoder().encode('not found page') } : { status: hit.status, contentType: hit.type, body: new TextEncoder().encode(hit.body) };
    },
    origin: 'https://synthetic.example',
    sha256: (bytes) => new TextDecoder().decode(bytes),
    sleep: async () => { sleeps += 1; clock += 15_000; },
    now: () => clock,
    notFoundProbePath: '__probe',
  };
  return { db, deps, served, fetched, provider, sleeps: () => sleeps };
}

function expectationFor(next: readonly RenditionPlacement[], previous: Uint8Array): VerifyExpectation {
  return {
    attemptId: A1, publicationId: P1, placements: next, files: [{ path: 'index.html', sha256: 'h2' }],
    previousLive: { attemptId: A0, publicationId: P0, providerVersionId: PREV_VERSION, snapshotSha256: sha256Hex(previous), snapshot: previous },
  };
}

/** The ledger, live site and sealed evidence for a publication moving from `previous` to `next`. */
function transition(previous: Uint8Array, next: Uint8Array) {
  const nextPlacements = placementsFromSnapshot(next);
  const removed = removedPlacements(placementsFromSnapshot(previous), nextPlacements);
  return { ...scenario(previous, nextPlacements), nextPlacements, removed, expect: expectationFor(nextPlacements, previous) };
}

const removedPaths = (before: Uint8Array, after: Uint8Array): string[] => removedPlacements(placementsFromSnapshot(before), placementsFromSnapshot(after)).map((p) => p.publicPath);

describe('verify (read-only, monotonic, never redeploys)', () => {
  const placements = [{ kind: 'collection' as const, publicPath: 'images/collections/sample/x.webp', renditionKey: 'k', sha256: 'h1' }];
  const setup = (): { db: FakeDb; deps: VerifyDeps; served: Map<string, { status: number; type: string; body: string }> } => {
    const { db, deps: d, served } = scenario(snapshotOf({}), placements);
    return { db, deps: d, served };
  };
  const expect = expectationFor(placements, snapshotOf({}));

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

describe('verify: removed-content absence against the previous live publication', () => {
  const before = snapshotOf({ cubes: [file(1, 'a'), file(2, 'b')], bowls: [file(3, 'c')] }, file(9, 'e'));
  const dropped = `/images/collections/cubes/${file(2, 'b')}`;
  const withoutTwo = (): Uint8Array => snapshotOf({ cubes: [file(1, 'a')], bowls: [file(3, 'c')] }, file(9, 'e'));

  test('a removed rendition answering 404 → verified, after the same proofs as before', async () => {
    const t = transition(before, withoutTwo());
    assert.deepEqual(t.removed.map((p) => `/${p.publicPath}`), [dropped]);
    assert.equal(await runVerify(t.deps, t.expect), 'verified');
    assert.ok(t.fetched.includes(dropped));
    assert.deepEqual(t.db.verifications.map((v) => [v.outcome, v.failure_class]), [['verified', null]]);
  });

  test('a removed rendition still answering 200 (or a redirect) → unverified removed_path_not_absent', async () => {
    for (const status of [200, 302]) {
      const t = transition(before, withoutTwo());
      t.served.set(dropped, { status, type: 'text/html', body: 'app shell' });
      assert.equal(await runVerify(t.deps, t.expect), 'unverified');
      assert.deepEqual(t.db.verifications.map((v) => v.failure_class), ['removed_path_not_absent']);
    }
  });

  test('a removed rendition serving its old bytes under any status → unverified removed_content_still_served', async () => {
    for (const status of [200, 203, 206, 404]) {
      const t = transition(before, withoutTwo());
      t.served.set(dropped, { status, type: 'image/webp', body: 'b'.repeat(64) });
      assert.equal(await runVerify(t.deps, t.expect), 'unverified');
      assert.deepEqual(t.db.verifications.map((v) => v.failure_class), ['removed_content_still_served']);
    }
  });

  test('a replacement retires the old path of the same photograph: still live → fails; absent → verified', async () => {
    const after = snapshotOf({ cubes: [file(1, 'a'), file(2, 'd')], bowls: [file(3, 'c')] }, file(9, 'e'));
    assert.deepEqual(removedPaths(before, after), [dropped.slice(1)]);
    const live = transition(before, after);
    live.served.set(dropped, { status: 200, type: 'image/webp', body: 'b'.repeat(64) });
    assert.equal(await runVerify(live.deps, live.expect), 'unverified');
    assert.equal(live.db.verifications[0]!.failure_class, 'removed_content_still_served');
    const gone = transition(before, after);
    assert.equal(await runVerify(gone.deps, gone.expect), 'verified');
  });

  test('an archive/removal (a collection emptied) retires its old paths; one still live → fails', async () => {
    const after = snapshotOf({ cubes: [file(1, 'a'), file(2, 'b')], bowls: [] }, file(9, 'e'));
    assert.deepEqual(removedPaths(before, after), [`images/collections/bowls/${file(3, 'c')}`]);
    const t = transition(before, after);
    t.served.set(`/images/collections/bowls/${file(3, 'c')}`, { status: 200, type: 'image/webp', body: 'c'.repeat(64) });
    assert.equal(await runVerify(t.deps, t.expect), 'unverified');
    assert.equal(t.db.verifications[0]!.failure_class, 'removed_content_still_served');
  });

  test('no removed paths → the existing verification passes unchanged, with no extra probes', async () => {
    const t = transition(before, before);
    assert.deepEqual(t.removed, []);
    assert.equal(await runVerify(t.deps, t.expect), 'verified');
    assert.deepEqual(t.fetched, [...t.nextPlacements.map((p) => `/${p.publicPath}`), '/', '/__probe']);
  });

  test('unchanged shared paths are never treated as removed', () => {
    const after = snapshotOf({ cubes: [file(1, 'a'), file(4, 'f')], bowls: [file(3, 'c')], plates: [file(5, '1')] }, file(9, 'e'));
    assert.deepEqual(removedPaths(before, after), [dropped.slice(1)]);
    // the same file moved to another collection is a different public path
    const moved = snapshotOf({ cubes: [file(1, 'a'), file(2, 'b')], plates: [file(3, 'c')] }, file(9, 'e'));
    assert.deepEqual(removedPaths(before, moved), [`images/collections/bowls/${file(3, 'c')}`]);
  });

  test('a metadata-only change removes nothing', async () => {
    const after = snapshotOf({ cubes: [{ file: file(1, 'a'), titleEl: 'νέος τίτλος', descriptionEn: 'new' }, { file: file(2, 'b'), titleEn: 'renamed' }], bowls: [file(3, 'c')] }, file(9, 'e'));
    assert.deepEqual(removedPaths(before, after), []);
    const t = transition(before, after);
    assert.equal(await runVerify(t.deps, t.expect), 'verified');
  });

  test('a reorder-only change removes nothing', async () => {
    const after = snapshotOf({ bowls: [file(3, 'c')], cubes: [file(2, 'b'), file(1, 'a')] }, file(9, 'e'));
    assert.deepEqual(removedPaths(before, after), []);
    const t = transition(before, after);
    assert.equal(await runVerify(t.deps, t.expect), 'verified');
  });

  test('a homepage-only publication retires only the old portrait; a catalogue publication keeps the portrait', async () => {
    const homepageOnly = snapshotOf({ cubes: [file(1, 'a'), file(2, 'b')], bowls: [file(3, 'c')] }, file(8, '7'));
    assert.deepEqual(removedPaths(before, homepageOnly), [`images/site/${file(9, 'e')}`]);
    const h = transition(before, homepageOnly);
    h.served.set(`/images/site/${file(9, 'e')}`, { status: 200, type: 'image/webp', body: 'e'.repeat(64) });
    assert.equal(await runVerify(h.deps, h.expect), 'unverified');
    assert.equal(h.db.verifications[0]!.failure_class, 'removed_content_still_served');

    const catalogueOnly = snapshotOf({ cubes: [file(1, 'a')], bowls: [file(3, 'c'), file(6, '2')] }, file(9, 'e'));
    assert.deepEqual(removedPaths(before, catalogueOnly), [dropped.slice(1)]);
    const c = transition(before, catalogueOnly);
    assert.ok(c.removed.every((p) => p.kind === 'collection'));
    assert.equal(await runVerify(c.deps, c.expect), 'verified');
  });

  test('the random missing-path 404 probe still runs on its own, after the removed-path proofs', async () => {
    const t = transition(before, withoutTwo());
    t.served.set('/__probe', { status: 200, type: 'text/html', body: 'shell' });
    assert.equal(await runVerify(t.deps, t.expect), 'unverified');
    assert.equal(t.db.verifications[0]!.failure_class, 'spa_fallback_answers_missing_file');
    const removedAt = t.fetched.indexOf(dropped);
    assert.ok(removedAt >= 0 && t.fetched.indexOf('/__probe') > removedAt);
  });

  test('verification never calls a provider write and writes only its own verification row', async () => {
    for (const stillLive of [false, true]) {
      const t = transition(before, withoutTwo());
      t.db.writes = [];
      if (stillLive) t.served.set(dropped, { status: 200, type: 'image/webp', body: 'b'.repeat(64) });
      await runVerify(t.deps, t.expect);
      assert.equal(t.provider.uploads, 0);
      assert.deepEqual(t.provider.activations, []);
      assert.deepEqual(t.provider.versions, []);
      assert.deepEqual(t.db.writes, ['INSERT INTO publication_verification']);
    }
  });
});

describe('verify: an untrustworthy previous-live base fails closed at once', () => {
  const before = snapshotOf({ cubes: [file(1, 'a'), file(2, 'b')] });
  const after = snapshotOf({ cubes: [file(1, 'a')] });
  const failsWith = async (t: ReturnType<typeof transition>, expect: VerifyExpectation, failureClass: string): Promise<void> => {
    assert.equal(await runVerify(t.deps, expect), 'unverified');
    assert.deepEqual(t.db.verifications.map((v) => [v.outcome, v.failure_class]), [['unverified', failureClass]]);
    assert.deepEqual(t.fetched, [], 'no live probe is trusted without a base');
    assert.equal(t.sleeps(), 0, 'a bad base is recorded at once, not polled');
  };

  test('no sealed evidence, or no earlier succeeded attempt in the ledger → previous_live_base_missing', async () => {
    const sealedNone = transition(before, after);
    await failsWith(sealedNone, { ...sealedNone.expect, previousLive: null }, 'previous_live_base_missing');
    const ledgerNone = transition(before, after);
    ledgerNone.db.events = ledgerNone.db.events.filter((e) => e.attempt_id !== A0);
    await failsWith(ledgerNone, ledgerNone.expect, 'previous_live_base_missing');
  });

  test('evidence that is not the ledger\'s previous succeeded attempt → previous_live_base_mismatch', async () => {
    for (const change of [{ attemptId: A2 }, { publicationId: P1 }, { providerVersionId: LIVE_VERSION }]) {
      const t = transition(before, after);
      await failsWith(t, { ...t.expect, previousLive: { ...t.expect.previousLive!, ...change } }, 'previous_live_base_mismatch');
    }
    // a newer succeeded attempt landed between select and this attempt
    const raced = transition(before, after);
    raced.db.events.splice(2, 0, { id: 't9', attempt_id: A2, publication_id: P0, event: 'succeeded', provider_version_id: 'v-race-0000000001', detail: null, created_at: raced.db.events[1]!.created_at.replace('.000Z', '.500Z') });
    await failsWith(raced, raced.expect, 'previous_live_base_mismatch');
  });

  test('tampered, unbound or malformed snapshot bytes → previous_live_evidence_invalid', async () => {
    const tampered = transition(before, after);
    await failsWith(tampered, { ...tampered.expect, previousLive: { ...tampered.expect.previousLive!, snapshot: after } }, 'previous_live_evidence_invalid');
    const unbound = transition(before, after);
    unbound.db.publications.delete(P0);
    await failsWith(unbound, unbound.expect, 'previous_live_evidence_invalid');
    const wrongHash = transition(before, after);
    await failsWith(wrongHash, { ...wrongHash.expect, previousLive: { ...wrongHash.expect.previousLive!, snapshotSha256: '0'.repeat(64) } }, 'previous_live_evidence_invalid');
    for (const bad of ['not json', '{"schemaVersion":3,"collections":{}}', '{"schemaVersion":2,"collections":{"cubes":[{"file":"x.webp"}]},"homepage":{}}']) {
      const bytes = new TextEncoder().encode(bad);
      const t = transition(before, after);
      t.db.publications.set(P0, { id: P0, content_hash: sha256Hex(bytes), snapshot_key: `snapshots/${sha256Hex(bytes)}.json` });
      await failsWith(t, { ...t.expect, previousLive: { ...t.expect.previousLive!, snapshotSha256: sha256Hex(bytes), snapshot: bytes } }, 'previous_live_evidence_invalid');
    }
  });

  test('removedSincePreviousLive never yields an empty removal set for a doubtful base', async () => {
    const t = transition(before, after);
    assert.deepEqual(await removedSincePreviousLive(t.db, t.expect, 't'), { removed: t.removed });
    assert.equal(t.removed.length, 1);
    assert.deepEqual(await removedSincePreviousLive(t.db, { ...t.expect, previousLive: null }, 't'), { failure: 'previous_live_base_missing' });
    assert.deepEqual(await removedSincePreviousLive(t.db, t.expect, 'no-such-event'), { failure: 'previous_live_base_missing' });
  });

  test('the sealed verify input parses strictly', () => {
    assert.equal(parsePreviousLive(null), null);
    const good = { attempt_id: A0, publication_id: P0, provider_version_id: PREV_VERSION, snapshot_sha256: 'a'.repeat(64), snapshot_b64: Buffer.from('{}').toString('base64') };
    assert.deepEqual(parsePreviousLive(good)!.snapshot, new Uint8Array(Buffer.from('{}')));
    for (const bad of [undefined, 'x', [], {}, { ...good, snapshot_b64: '' }, { ...good, attempt_id: 7 }]) {
      assert.throws(() => parsePreviousLive(bad), /previous live evidence is malformed/);
    }
  });
});
