/**
 * fe-policy: the trusted pull_request_target evaluator. Runs the
 * DEFAULT-BRANCH copy of this file; never checks out or executes PR code.
 * PR files are fetched through the API at the head SHA and judged as data.
 * The verdict is published as the `fe-policy` check run by the
 * fe-control-policy GitHub App (an installation token minted from the App
 * key held only in the control-policy environment), so branch protection
 * can pin the required check to that App's ID.
 */
import { createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { FailClosedError } from '../lib/errors.ts';
import { CONTROL_REPOSITORY } from '../lib/github.ts';
import { checkJobEnv, requireEnv } from '../lib/job-env.ts';
import { parseManifest, type ReleaseManifest } from '../lib/manifest.ts';
import { verifiedTargetConfig } from '../lib/target-config.ts';
import { evaluatePullRequest, parseActionAllowlist, type PolicyVerdict } from './policy-engine.ts';

export const CHECK_NAME = 'fe-policy';
const API = 'https://api.github.com';

type Json = Record<string, unknown>;

async function call(token: string, method: string, url: string, body?: unknown, accept = 'application/vnd.github+json'): Promise<Response> {
  return fetch(url.startsWith('http') ? url : `${API}${url}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, Accept: accept, 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'fe-control-policy', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function json(token: string, url: string): Promise<unknown> {
  const response = await call(token, 'GET', url);
  if (response.status !== 200) throw new FailClosedError(`GitHub API read failed (${response.status})`);
  return response.json();
}

async function raw(token: string, path: string, ref: string): Promise<string | null> {
  const response = await call(token, 'GET', `/repos/${CONTROL_REPOSITORY}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${ref}`, undefined, 'application/vnd.github.raw+json');
  if (response.status === 404) return null;
  if (response.status !== 200) throw new FailClosedError(`content read failed (${response.status})`);
  return response.text();
}

/** The accepted manifest history of one target on the base branch, oldest first. */
async function manifestHistory(token: string, baseSha: string, target: 'test' | 'prod'): Promise<ReleaseManifest[]> {
  const commits = await json(token, `/repos/${CONTROL_REPOSITORY}/commits?sha=${baseSha}&path=release/${target}.json&per_page=100`) as Json[];
  const history: ReleaseManifest[] = [];
  for (const commit of [...commits].reverse()) {
    const text = await raw(token, `release/${target}.json`, String(commit.sha));
    if (text !== null) history.push(parseManifest(JSON.parse(text) as unknown, target));
  }
  return history;
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/** RS256 App JWT (10-minute ceiling per GitHub; 9 minutes used). */
export function appJwt(appId: string, privateKeyPem: string, nowSeconds = Math.floor(Date.now() / 1000)): string {
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({ iat: nowSeconds - 60, exp: nowSeconds + 540, iss: appId }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${base64url(signer.sign(privateKeyPem))}`;
}

export function summarize(verdict: PolicyVerdict): string {
  const lines = verdict.findings.slice(0, 50).map((f) => `- \`${f.rule}\` ${f.path.replace(/[`<>]/g, '')}: ${f.detail.replace(/[`<>]/g, '')}`);
  return [`PR class: ${verdict.prClass ?? 'invalid'}`, `Findings: ${verdict.findings.length}`, ...lines].join('\n');
}

export async function main(env: NodeJS.ProcessEnv): Promise<void> {
  checkJobEnv('policy', env);
  const event = JSON.parse(readFileSync(requireEnv(env, 'GITHUB_EVENT_PATH'), 'utf8')) as Json;
  const pr = event.pull_request as Json;
  if (env.GITHUB_EVENT_NAME !== 'pull_request_target' || typeof pr !== 'object' || pr === null) throw new FailClosedError('fe-policy runs only for pull_request_target');
  const base = pr.base as Json;
  const head = pr.head as Json;
  const headSha = String(head.sha);
  if (!/^[0-9a-f]{40}$/.test(headSha)) throw new FailClosedError('head SHA is malformed');
  const headRepoIsBase = (head.repo as Json | null)?.full_name === CONTROL_REPOSITORY && (base.repo as Json).full_name === CONTROL_REPOSITORY;
  const token = requireEnv(env, 'GH_TOKEN');

  const changed = new Map<string, string | null>();
  if (headRepoIsBase) {
    for (let page = 1; page <= 30; page += 1) {
      const files = await json(token, `/repos/${CONTROL_REPOSITORY}/pulls/${Number(pr.number)}/files?per_page=100&page=${page}`) as Json[];
      for (const file of files) {
        const path = String(file.filename);
        changed.set(path, file.status === 'removed' ? null : await raw(token, path, headSha));
        if (file.previous_filename !== undefined) changed.set(String(file.previous_filename), null);
      }
      if (files.length < 100) break;
    }
  }
  const baseSha = String(base.sha);
  const verdict = evaluatePullRequest({
    baseRef: String(base.ref),
    headRepoIsBase,
    changed,
    actions: parseActionAllowlist(JSON.parse(readFileSync('config/actions.json', 'utf8')) as unknown),
    history: headRepoIsBase && [...changed.keys()].some((p) => p.startsWith('release/'))
      ? { test: await manifestHistory(token, baseSha, 'test'), prod: await manifestHistory(token, baseSha, 'prod') }
      : { test: [], prod: [] },
  });

  const config = verifiedTargetConfig(env.TARGET_CONFIG_JSON, 'control-policy', 'prod');
  const jwt = appJwt(config.fields.policy_app_id!, requireEnv(env, 'CONTROL_POLICY_APP_PRIVATE_KEY'));
  const minted = await call(jwt, 'POST', `/app/installations/${config.fields.policy_app_installation_id}/access_tokens`, {
    repositories: [CONTROL_REPOSITORY.split('/')[1]],
    permissions: { checks: 'write' },
  });
  if (minted.status !== 201) throw new FailClosedError(`App installation token could not be minted (${minted.status})`);
  const appToken = String(((await minted.json()) as Json).token);
  const created = await call(appToken, 'POST', `/repos/${CONTROL_REPOSITORY}/check-runs`, {
    name: CHECK_NAME,
    head_sha: headSha,
    status: 'completed',
    conclusion: verdict.pass ? 'success' : 'failure',
    output: { title: verdict.pass ? 'fe-policy passed' : 'fe-policy failed', summary: summarize(verdict) },
  });
  if (created.status !== 201) throw new FailClosedError(`check run could not be created (${created.status})`);
  console.log(`FE_POLICY=${verdict.pass ? 'PASS' : 'FAIL'} findings=${verdict.findings.length}`);
  if (!verdict.pass) process.exitCode = 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.env).catch((error: unknown) => {
    console.error(`FE_POLICY=ERROR ${error instanceof FailClosedError ? error.message : 'failed'}`);
    process.exit(1);
  });
}
