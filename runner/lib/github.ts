/**
 * GitHub Actions runtime helpers: run identity, step outputs, fixed status
 * lines, and the release-tip assertion. Status lines carry fixed tokens and
 * counts only — never identifiers, keys, paths of private objects or values.
 */
import { appendFileSync } from 'node:fs';

import { FailClosedError } from './errors.ts';
import { requireEnv } from './job-env.ts';

export const RELEASE_REF = 'refs/heads/production-release';
export const CONTROL_REPOSITORY = 'gaimeore/fine-elements-release-control';

export interface RunContext {
  readonly repository: string;
  readonly workflowRef: string;
  readonly runId: string;
  readonly runAttempt: string;
  readonly sha: string;
  readonly ref: string;
}

export function runContextFrom(env: NodeJS.ProcessEnv): RunContext {
  const context: RunContext = {
    repository: requireEnv(env, 'GITHUB_REPOSITORY'),
    workflowRef: requireEnv(env, 'GITHUB_WORKFLOW_REF'),
    runId: requireEnv(env, 'GITHUB_RUN_ID'),
    runAttempt: requireEnv(env, 'GITHUB_RUN_ATTEMPT'),
    sha: requireEnv(env, 'GITHUB_SHA'),
    ref: requireEnv(env, 'GITHUB_REF'),
  };
  if (!/^[0-9]+$/.test(context.runId) || !/^[0-9]+$/.test(context.runAttempt)) throw new FailClosedError('run identity is malformed');
  if (!/^[0-9a-f]{40}$/.test(context.sha)) throw new FailClosedError('GITHUB_SHA is malformed');
  return context;
}

/** Privileged jobs only ever run from the protected release branch of this repository. */
export function assertReleaseRun(context: RunContext): void {
  if (context.repository !== CONTROL_REPOSITORY) throw new FailClosedError('not the release-control repository');
  if (context.ref !== RELEASE_REF) throw new FailClosedError('privileged jobs run only on production-release');
  if (!context.workflowRef.startsWith(`${CONTROL_REPOSITORY}/.github/workflows/`) || !context.workflowRef.endsWith(`@${RELEASE_REF}`)) {
    throw new FailClosedError('workflow does not come from production-release');
  }
}

const OUTPUT_VALUE = /^[A-Za-z0-9._:-]{1,200}$/;

/** Writes one step output; values are restricted to a safe single-line alphabet. */
export function setStepOutput(env: NodeJS.ProcessEnv, name: string, value: string): void {
  if (!/^[a-z0-9_]{1,64}$/.test(name) || !OUTPUT_VALUE.test(value)) throw new FailClosedError('refusing an unsafe step output');
  appendFileSync(requireEnv(env, 'GITHUB_OUTPUT'), `${name}=${value}\n`, 'utf8');
}

/** The only line a privileged step prints: a fixed token plus non-identifying counts. */
export function status(token: string, counts: Readonly<Record<string, number | string>> = {}): void {
  if (!/^FE_[A-Z0-9_]+=[A-Z_]+$/.test(token)) throw new FailClosedError('status token is malformed');
  const tail = Object.entries(counts).map(([key, value]) => {
    if (!/^[a-z_]+$/.test(key) || !/^[A-Za-z0-9_]{1,40}$/.test(String(value))) throw new FailClosedError('status count is malformed');
    return ` ${key}=${value}`;
  }).join('');
  console.log(`${token}${tail}`);
}

/**
 * Re-runs reuse the original GITHUB_SHA, so a stale run must find that the
 * protected release branch has moved on and stop.
 */
export async function assertReleaseTip(
  context: RunContext,
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  assertReleaseRun(context);
  const response = await fetchImpl(`https://api.github.com/repos/${context.repository}/git/ref/heads/production-release`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'fe-release-control' },
  });
  if (response.status !== 200) throw new FailClosedError(`release tip lookup failed (${response.status})`);
  const body = await response.json() as { object?: { sha?: unknown } };
  if (body.object?.sha !== context.sha) throw new FailClosedError('this run is not at the current production-release tip');
}
