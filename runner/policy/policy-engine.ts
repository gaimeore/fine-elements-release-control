/**
 * The release-control policy (server/ARCHITECTURE.md §19 "Control policy").
 * Pure: everything it judges is DATA (file contents as strings, parsed with
 * a YAML/JSON parser), so the trusted pull_request_target job can evaluate a
 * PR without checking out or executing any PR file.
 *
 * Rules: workflow trigger allowlist; full-SHA action pins from an allowlist;
 * no cache; secrets only in environment-bound jobs and only that
 * environment's own family; one environment per job; permission caps; the
 * production-release assertion; control-policy referenced only by
 * policy.yml; the scheduler's secretless shape; the sandbox template
 * invariants; the content allowlist/denylist; config table schemas; PR
 * class 1 (one manifest) / class 2 (code), mixed forbidden.
 */
import { parse } from 'yaml';

import { FailClosedError } from '../lib/errors.ts';
import { parseManifest, validateManifestHistory, validateManifestSuccessor, validateProdPromotion, type ReleaseManifest } from '../lib/manifest.ts';
import { parseRecipientTable } from '../lib/recipients.ts';
import { parseFingerprintTable } from '../lib/target-config.ts';

export interface Finding {
  readonly rule: string;
  readonly path: string;
  readonly detail: string;
}

// ---------------------------------------------------------------------------
// Environments and their only secrets (the credential families)
// ---------------------------------------------------------------------------

const FAMILY: Readonly<Record<string, (T: string) => readonly string[]>> = {
  'backup-verify': (T) => ['TARGET_CONFIG_JSON', `${T}_BACKUP_VERIFIER_DATABASE_URL`, `B2_${T}_RESTORE_KEY_ID`, `B2_${T}_RESTORE_APPLICATION_KEY`, `${T}_BACKUP_VERIFY_HANDOFF_KEY`],
  'backup-write': (T) => ['TARGET_CONFIG_JSON', `R2_${T}_SOURCE_ACCESS_KEY_ID`, `R2_${T}_SOURCE_SECRET_ACCESS_KEY`, `B2_${T}_WRITER_KEY_ID`, `B2_${T}_WRITER_APPLICATION_KEY`, `${T}_BACKUP_WRITE_HANDOFF_KEY`],
  'deploy-prepare': (T) => ['TARGET_CONFIG_JSON', `${T}_DEPLOY_RUNNER_DATABASE_URL`, `R2_${T}_DEPLOY_READER_ACCESS_KEY_ID`, `R2_${T}_DEPLOY_READER_SECRET_ACCESS_KEY`],
  'source-fetch': (T) => [`${T}_SOURCE_DEPLOY_KEY`],
  build: (T) => [`${T}_BUILD_HANDOFF_KEY`],
  deploy: (T) => ['TARGET_CONFIG_JSON', `${T}_DEPLOY_RUNNER_DATABASE_URL`, `CLOUDFLARE_${T}_PUBLIC_DEPLOY_TOKEN`, `${T}_DEPLOY_HANDOFF_KEY`],
  verify: (T) => ['TARGET_CONFIG_JSON', `${T}_DEPLOY_RUNNER_DATABASE_URL`, `CLOUDFLARE_${T}_PUBLIC_READ_TOKEN`, `${T}_VERIFY_HANDOFF_KEY`],
};

/** environment name → the exact secret names a job bound to it may reference. */
export const ENVIRONMENT_SECRETS: ReadonlyMap<string, readonly string[]> = new Map([
  ...(['test', 'prod'] as const).flatMap((t) => Object.entries(FAMILY).map(([kind, names]) => [`${t}-${kind}`, names(t.toUpperCase())] as const)),
  ['control-policy', ['TARGET_CONFIG_JSON', 'CONTROL_POLICY_APP_PRIVATE_KEY']] as const,
]);

const RELEASE_ASSERTION = 'test "$GITHUB_REF" = "refs/heads/production-release"';
const POLICY_WORKFLOW = '.github/workflows/policy.yml';
const ALLOWED_TRIGGERS = new Set(['workflow_dispatch', 'pull_request', 'push', 'schedule', 'pull_request_target']);

export interface ActionAllowlist {
  readonly allowed: Readonly<Record<string, { readonly sha: string; readonly version: string }>>;
}

export function parseActionAllowlist(json: unknown): ActionAllowlist {
  const raw = json as { schema?: unknown; allowed?: Record<string, { sha?: unknown; version?: unknown }> };
  if (typeof raw !== 'object' || raw === null || raw.schema !== 'fe-actions/1' || typeof raw.allowed !== 'object' || raw.allowed === null) {
    throw new FailClosedError('action allowlist is malformed');
  }
  const permitted = ['actions/checkout', 'actions/setup-node', 'actions/upload-artifact', 'actions/download-artifact'];
  for (const [name, pin] of Object.entries(raw.allowed)) {
    if (!permitted.includes(name)) throw new FailClosedError('the action allowlist may name only the four accepted GitHub actions');
    if (typeof pin.sha !== 'string' || !/^[0-9a-f]{40}$/.test(pin.sha) || typeof pin.version !== 'string' || !/^v\d+\.\d+\.\d+$/.test(pin.version)) {
      throw new FailClosedError('action pins must be full 40-hex SHAs with a version');
    }
  }
  return raw as ActionAllowlist;
}

type Rec = Record<string, unknown>;
const isRec = (value: unknown): value is Rec => typeof value === 'object' && value !== null && !Array.isArray(value);

function triggersOf(on: unknown): string[] {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (isRec(on)) return Object.keys(on);
  return [];
}

/** Lints one workflow file (as text). */
export function lintWorkflow(file: string, text: string, actions: ActionAllowlist): Finding[] {
  const findings: Finding[] = [];
  const add = (rule: string, detail: string): void => { findings.push({ rule, path: file, detail }); };
  let doc: unknown;
  try { doc = parse(text, { maxAliasCount: 0, uniqueKeys: true }); } catch { add('workflow-yaml', 'workflow is not valid YAML'); return findings; }
  if (!isRec(doc)) { add('workflow-yaml', 'workflow root must be a map'); return findings; }

  const isPolicy = file === POLICY_WORKFLOW;
  const triggers = triggersOf(doc.on);
  for (const trigger of triggers) {
    if (!ALLOWED_TRIGGERS.has(trigger)) add('trigger-allowlist', `forbidden trigger ${trigger}`);
  }
  if (triggers.includes('pull_request_target') && !isPolicy) add('trigger-allowlist', 'pull_request_target is reserved for policy.yml');
  if (isPolicy && (triggers.length !== 1 || triggers[0] !== 'pull_request_target')) add('trigger-allowlist', 'policy.yml runs on pull_request_target only');
  const isScheduler = triggers.includes('schedule');
  if (isScheduler && triggers.length !== 1) add('trigger-allowlist', 'the scheduler has only the schedule trigger');
  const dispatch = isRec(doc.on) ? doc.on.workflow_dispatch : undefined;
  if (isRec(dispatch) && dispatch.inputs !== undefined) add('dispatch-inputs', 'workflow_dispatch takes no inputs');

  if (!isRec(doc.permissions) || Object.keys(doc.permissions).length !== 0) add('permissions', 'workflow-level permissions must be {}');
  if (!isRec(doc.jobs)) { add('workflow-yaml', 'workflow has no jobs'); return findings; }

  const jobs = Object.entries(doc.jobs);
  const privileged = jobs.some(([, job]) => isRec(job) && job.environment !== undefined);
  if (privileged && !isPolicy) {
    if (triggers.length !== 1 || triggers[0] !== 'workflow_dispatch') add('trigger-allowlist', 'privileged workflows run on workflow_dispatch only');
    const concurrency = doc.concurrency;
    if (!isRec(concurrency) || concurrency['cancel-in-progress'] !== false || typeof concurrency.group !== 'string') add('concurrency', 'privileged workflows serialize per target with cancel-in-progress: false');
  }
  if (/\bsecrets\.GITHUB_TOKEN\b/.test(text)) add('secrets', 'secrets.GITHUB_TOKEN is not used; github.token is mapped explicitly');

  for (const [name, job] of jobs) {
    const where = `${file}#${name}`;
    const jadd = (rule: string, detail: string): void => { findings.push({ rule, path: where, detail }); };
    if (!isRec(job)) { jadd('workflow-yaml', 'job must be a map'); continue; }
    if (job.uses !== undefined) jadd('reusable-workflow', 'reusable workflow calls are forbidden');
    if (job.container !== undefined || job.services !== undefined) jadd('containers', 'job containers and services are forbidden');
    if (job['runs-on'] !== 'ubuntu-24.04') jadd('runs-on', 'jobs run on the pinned ubuntu-24.04 label');

    const env = job.environment;
    const envName = typeof env === 'string' ? env : isRec(env) && typeof env.name === 'string' ? env.name : undefined;
    if (env !== undefined && envName === undefined) jadd('environment', 'environment must be a single name');
    if (envName !== undefined && !ENVIRONMENT_SECRETS.has(envName)) jadd('environment', `unknown environment ${envName}`);
    if (envName === 'control-policy' && !isPolicy) jadd('control-policy', 'only policy.yml may reference the control-policy environment');

    const perms = job.permissions;
    if (!isRec(perms)) jadd('permissions', 'every job declares its permissions');
    else {
      for (const [scope, level] of Object.entries(perms)) {
        const allowed = (scope === 'contents' && level === 'read')
          || (scope === 'pull-requests' && level === 'read' && isPolicy)
          || (scope === 'actions' && level === 'write' && isScheduler);
        if (!allowed) jadd('permissions', `permission ${scope}: ${String(level)} is above the cap`);
      }
    }

    const steps = Array.isArray(job.steps) ? job.steps.filter(isRec) : [];
    const jobText = JSON.stringify(job);
    const secretRefs = [...jobText.matchAll(/secrets\.([A-Za-z0-9_]+)/g)].map((m) => m[1]!);
    if (secretRefs.length > 0 && envName === undefined) jadd('secrets', 'secrets are referenced only in environment-bound jobs');
    if (envName !== undefined) {
      const family = ENVIRONMENT_SECRETS.get(envName) ?? [];
      for (const ref of secretRefs) if (!family.includes(ref)) jadd('credential-family', `${ref} is not in the ${envName} family`);
    }
    if (/\bvars\./.test(jobText) && !isScheduler && !/vars\.FE_DEPLOY_PAUSED_(TEST|PROD)/.test(jobText)) jadd('variables', 'unexpected repository variable reference');

    if (envName !== undefined && envName !== 'control-policy') {
      if (steps[0]?.run !== RELEASE_ASSERTION) jadd('release-assertion', 'the first step must assert production-release');
      if (!steps.some((step) => typeof step.run === 'string' && step.run.includes('runner/lib/assert-release-tip.ts'))) jadd('release-assertion', 'the job must assert the current release tip');
      const expected = /^(test|prod)-/.exec(envName)?.[1];
      const targets = steps.flatMap((step) => (isRec(step.env) && step.env.FE_TARGET !== undefined ? [String(step.env.FE_TARGET)] : []));
      if (targets.length === 0 || targets.some((t) => t !== expected)) jadd('target', 'every task step declares FE_TARGET equal to its environment target');
      const runs = steps.flatMap((step) => (typeof step.run === 'string' ? [step.run] : []));
      if (runs.some((run) => /--target (test|prod)/.test(run) && !run.includes(`--target ${expected}`))) jadd('target', 'CLI --target does not match the environment');
    }

    for (const step of steps) {
      if (typeof step.run === 'string' && step.run.includes('${{')) jadd('shell-interpolation', 'expressions are passed through env, never interpolated into run');
      if (step.uses !== undefined) {
        const uses = String(step.uses);
        const [action, ref] = uses.split('@');
        const pin = action !== undefined ? actions.allowed[action] : undefined;
        if (pin === undefined || ref !== pin.sha) jadd('action-pin', `${uses} is not an allowlisted full-SHA pin`);
        const withBlock = isRec(step.with) ? step.with : {};
        if (action === 'actions/checkout') {
          if (withBlock['persist-credentials'] !== false) jadd('checkout', 'checkout must set persist-credentials: false');
          if (withBlock.ref !== undefined || withBlock.repository !== undefined) jadd('checkout', 'checkout never selects another ref or repository');
        }
        if (action === 'actions/setup-node' && withBlock.cache !== undefined) jadd('cache', 'setup-node cache is forbidden');
      }
    }
    if (/actions\/cache/.test(jobText)) jadd('cache', 'actions/cache is forbidden');

    if (isScheduler) {
      if (envName !== undefined || steps.some((s) => s.uses !== undefined) || secretRefs.length > 0) jadd('scheduler', 'the scheduler has no environment, no checkout and no secret');
      if (!/^vars\.FE_BACKUP_SCHEDULER_(TEST|PROD)_ENABLED == 'true'$/.test(String(job.if))) jadd('scheduler', 'each scheduler job is gated by its enable switch');
      if (!steps.every((s) => typeof s.run === 'string' && /^gh workflow run backup-(test|prod)\.yml --repo "\$GITHUB_REPOSITORY" --ref production-release$/.test(s.run))) {
        jadd('scheduler', 'the scheduler only dispatches a backup workflow on production-release');
      }
    }
  }
  // The policy job fetches the base definition only (checkout above has no ref; pull_request_target's own ref).
  if (isPolicy && /github\.event\.pull_request\.head/.test(text)) add('policy', 'policy.yml never references the PR head');
  return findings;
}

// ---------------------------------------------------------------------------
// Sandbox template invariants (text of runner/build/sandbox.ts)
// ---------------------------------------------------------------------------

/**
 * Exact argument-vector snippets (with their array punctuation, so the
 * invariant checker's own source cannot satisfy them).
 */
const SANDBOX_REQUIRED = [
  "'--network', 'none',",
  "'--cap-drop', 'ALL',",
  "'--security-opt', 'no-new-privileges:true',",
  "'--read-only',",
  "'--log-driver', 'none',",
  "'--ulimit', 'core=0',",
  "'--ipc', 'private', '--cgroupns', 'private',",
  "'npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund',",
  "SANDBOX_UID = '10001:10001'",
  "'exec </dev/null >/out/.build.log 2>&1;',",
];

export function lintSandboxSource(file: string, text: string): Finding[] {
  return SANDBOX_REQUIRED.filter((needle) => !text.includes(needle)).map((needle) => ({ rule: 'sandbox-template', path: file, detail: `missing ${needle}` }));
}

export function lintBuildWrapper(file: string, text: string): Finding[] {
  const findings: Finding[] = [];
  for (const needle of [
    "assertSandboxInvariants(depsArgs, 'dependency')", "assertSandboxInvariants(buildArgs, 'build')", "stdio: ['ignore', fd, fd]",
    // the build is time-bounded, and the container is force-removed right after the bound
    "host.run('timeout', ['--kill-after=15s', '1200', 'docker', ...buildArgs]", "host.run('docker', ['rm', '-f', 'fe-build']",
  ]) {
    if (!text.includes(needle)) findings.push({ rule: 'sandbox-template', path: file, detail: `missing ${needle}` });
  }
  if (/stdio:\s*'inherit'/.test(text)) findings.push({ rule: 'sandbox-template', path: file, detail: 'sandbox output may never inherit the job log' });
  return findings;
}

// ---------------------------------------------------------------------------
// Content allowlist / denylist
// ---------------------------------------------------------------------------

const PATH_ALLOW = [
  /^README\.md$/, /^SECURITY\.md$/, /^package\.json$/, /^package-lock\.json$/, /^tsconfig\.json$/, /^\.gitignore$/,
  /^\.github\/workflows\/[a-z0-9-]+\.yml$/, /^runner\/[a-z0-9/_-]+\.ts$/, /^tests\/[a-z0-9/_.-]+\.ts$/,
  /^schemas\/[a-z0-9-]+\.json$/, /^config\/(target-fingerprints|recipients|sandbox|actions)\.json$/,
  /^release\/(test|prod)\.json$/, /^docs\/[a-z0-9-]+\.md$/,
];

/** Synthetic values used by tests; anything else of these shapes is treated as real. */
const SYNTHETIC_HEX32 = new Set(['0123456789abcdef0123456789abcdef']);

const DENY: readonly { readonly rule: string; readonly pattern: RegExp }[] = [
  { rule: 'credential', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { rule: 'credential', pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{20,}/ },
  { rule: 'credential', pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { rule: 'credential', pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/'"@:]+:[^\s/'"@]+@/i },
  { rule: 'credential', pattern: /"d"\s*:\s*"[A-Za-z0-9_-]{43}"/ },
  { rule: 'private-identifier', pattern: /fine-elements-(private|public)-(test|prod)|fine-elements-(test|prod)-backup/ },
  { rule: 'private-identifier', pattern: /\b[a-z]+-[a-z]+-\d{8}\b/ },
  { rule: 'private-identifier', pattern: /\b(ep|br)-[a-z]+-[a-z]+-[a-z0-9]{8}\b/ },
  { rule: 'private-hostname', pattern: /fine-elements\.gr|\.workers\.dev|neon\.tech|cloudflareaccess\.com/i },
  { rule: 'private-source', pattern: /from ['"](react|react-dom|@\/)['"/]/ },
];

export function scanContent(file: string, text: string): Finding[] {
  const findings: Finding[] = [];
  if (!PATH_ALLOW.some((rule) => rule.test(file))) findings.push({ rule: 'path-allowlist', path: file, detail: 'path is not on the public content allowlist' });
  for (const { rule, pattern } of DENY) if (pattern.test(text)) findings.push({ rule, path: file, detail: `matches ${rule} pattern` });
  for (const match of text.matchAll(/(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])/g)) {
    if (!SYNTHETIC_HEX32.has(match[0])) findings.push({ rule: 'private-identifier', path: file, detail: 'a 32-hex identifier' });
  }
  for (const match of text.matchAll(/4_z([0-9a-f]{24})/g)) {
    if (!/^0+$/.test(match[1]!)) findings.push({ rule: 'private-identifier', path: file, detail: 'a real B2 bucket or file identifier' });
  }
  for (const match of text.matchAll(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi)) {
    if (!match[0].startsWith('00000000-0000-')) findings.push({ rule: 'private-identifier', path: file, detail: 'a non-synthetic UUID' });
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Whole-tree and PR evaluation
// ---------------------------------------------------------------------------

function parseJson(file: string, text: string, findings: Finding[]): unknown {
  try { return JSON.parse(text) as unknown; } catch { findings.push({ rule: 'json', path: file, detail: 'invalid JSON' }); return undefined; }
}

/** Every rule that applies to a set of files (all of the tree, or the changed files at a PR head). */
export function evaluateFiles(files: ReadonlyMap<string, string>, actions: ActionAllowlist): Finding[] {
  const findings: Finding[] = [];
  for (const [file, text] of files) {
    findings.push(...scanContent(file, text));
    if (file.startsWith('.github/workflows/')) findings.push(...lintWorkflow(file, text, actions));
    if (file === 'runner/build/sandbox.ts') findings.push(...lintSandboxSource(file, text));
    if (file === 'runner/build/build-wrapper.ts') findings.push(...lintBuildWrapper(file, text));
    const guarded = (parseFn: (json: unknown) => unknown): void => {
      const json = parseJson(file, text, findings);
      if (json === undefined) return;
      try { parseFn(json); } catch (error) { findings.push({ rule: 'config', path: file, detail: (error as Error).message }); }
    };
    if (file === 'config/target-fingerprints.json') guarded(parseFingerprintTable);
    if (file === 'config/recipients.json') guarded(parseRecipientTable);
    if (file === 'config/actions.json') guarded(parseActionAllowlist);
    if (/^release\/(test|prod)\.json$/.test(file)) guarded((json) => parseManifest(json, file.includes('prod') ? 'prod' : 'test'));
  }
  return findings;
}

export type PrClass = 1 | 2;

export interface PullRequestInput {
  readonly baseRef: string;
  readonly headRepoIsBase: boolean;
  /** Changed paths; removed files map to null. */
  readonly changed: ReadonlyMap<string, string | null>;
  readonly actions: ActionAllowlist;
  /** Accepted manifest history on the base branch, oldest first, per target. */
  readonly history: { readonly test: readonly ReleaseManifest[]; readonly prod: readonly ReleaseManifest[] };
}

export interface PolicyVerdict {
  readonly pass: boolean;
  readonly prClass: PrClass | null;
  readonly findings: readonly Finding[];
}

export function evaluatePullRequest(input: PullRequestInput): PolicyVerdict {
  const findings: Finding[] = [];
  if (!input.headRepoIsBase) findings.push({ rule: 'fork', path: '(pull request)', detail: 'pull requests from forks are never accepted' });
  if (input.baseRef !== 'main' && input.baseRef !== 'production-release') findings.push({ rule: 'base', path: '(pull request)', detail: 'unexpected base branch' });
  const paths = [...input.changed.keys()];
  const manifests = paths.filter((p) => p.startsWith('release/'));
  let prClass: PrClass | null = null;
  if (manifests.length > 0) {
    if (paths.length !== 1 || !/^release\/(test|prod)\.json$/.test(manifests[0]!)) findings.push({ rule: 'pr-class', path: '(pull request)', detail: 'a manifest PR changes exactly one release manifest and nothing else' });
    else prClass = 1;
  } else {
    prClass = 2;
  }
  if (prClass === 1) {
    const file = manifests[0]!;
    const target = file.includes('prod') ? 'prod' : 'test';
    const text = input.changed.get(file);
    if (input.baseRef !== 'production-release') findings.push({ rule: 'pr-class', path: file, detail: 'release manifests change only on production-release' });
    if (text === null || text === undefined) findings.push({ rule: 'manifest-chain', path: file, detail: 'a release manifest is never removed' });
    else {
      try {
        const next = parseManifest(JSON.parse(text) as unknown, target);
        const history = input.history[target];
        validateManifestHistory(history);
        validateManifestSuccessor(history.at(-1) ?? null, next);
        if (target === 'prod') validateProdPromotion(next, input.history.test);
      } catch (error) {
        findings.push({ rule: 'manifest-chain', path: file, detail: error instanceof Error ? error.message : 'invalid manifest' });
      }
    }
  }
  const present = new Map([...input.changed].filter((entry): entry is [string, string] => entry[1] !== null));
  findings.push(...evaluateFiles(present, input.actions));
  for (const [file, text] of input.changed) {
    if (text === null && (file.startsWith('.github/workflows/policy.yml') || file.startsWith('runner/policy/') || file.startsWith('config/'))) {
      findings.push({ rule: 'protected-file', path: file, detail: 'policy and configuration files are never removed' });
    }
  }
  return { pass: findings.length === 0, prClass, findings };
}
