/**
 * The credential split, per job (server/ARCHITECTURE.md §19 "Release control
 * plane"): each job holds exactly its own credential family. A job refuses
 * to start when a required variable is missing or when ANY other
 * credential-shaped variable is present. Errors name variables, never values.
 */
import { FailClosedError } from './errors.ts';

export type JobKind =
  | 'backup-scan'
  | 'backup-write'
  | 'backup-verify'
  | 'deploy-prepare'
  | 'source-fetch'
  | 'build'
  | 'deploy'
  | 'deploy-verify'
  | 'policy'
  | 'release-tip';

export const JOB_ENV: Readonly<Record<JobKind, readonly string[]>> = {
  'backup-scan': ['TARGET_CONFIG_JSON', 'BACKUP_VERIFIER_DATABASE_URL', 'B2_RESTORE_KEY_ID', 'B2_RESTORE_APPLICATION_KEY'],
  'backup-write': ['TARGET_CONFIG_JSON', 'R2_SOURCE_ACCESS_KEY_ID', 'R2_SOURCE_SECRET_ACCESS_KEY', 'B2_WRITER_KEY_ID', 'B2_WRITER_APPLICATION_KEY', 'FE_HANDOFF_PRIVATE_KEY'],
  'backup-verify': ['TARGET_CONFIG_JSON', 'BACKUP_VERIFIER_DATABASE_URL', 'B2_RESTORE_KEY_ID', 'B2_RESTORE_APPLICATION_KEY', 'FE_HANDOFF_PRIVATE_KEY'],
  'deploy-prepare': ['TARGET_CONFIG_JSON', 'DEPLOY_RUNNER_DATABASE_URL', 'R2_DEPLOY_READER_ACCESS_KEY_ID', 'R2_DEPLOY_READER_SECRET_ACCESS_KEY'],
  'source-fetch': ['SOURCE_DEPLOY_KEY'],
  build: ['FE_HANDOFF_PRIVATE_KEY'],
  deploy: ['TARGET_CONFIG_JSON', 'DEPLOY_RUNNER_DATABASE_URL', 'CLOUDFLARE_API_TOKEN', 'FE_HANDOFF_PRIVATE_KEY'],
  'deploy-verify': ['TARGET_CONFIG_JSON', 'DEPLOY_RUNNER_DATABASE_URL', 'CLOUDFLARE_API_TOKEN', 'FE_HANDOFF_PRIVATE_KEY'],
  policy: ['TARGET_CONFIG_JSON', 'CONTROL_POLICY_APP_PRIVATE_KEY', 'GH_TOKEN'],
  'release-tip': ['GH_TOKEN'],
};

const CREDENTIAL_EXACT = new Set([
  'DATABASE_URL', 'GITHUB_TOKEN', 'GH_TOKEN', 'CLOUDFLARE_API_TOKEN', 'TARGET_CONFIG_JSON',
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'NPM_TOKEN', 'NODE_AUTH_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'SOURCE_DEPLOY_KEY',
  'FE_HANDOFF_PRIVATE_KEY', 'CONTROL_POLICY_APP_PRIVATE_KEY',
]);
const CREDENTIAL_PREFIXES = ['DATABASE_URL_', 'B2_', 'R2_'];
const CREDENTIAL_SUFFIXES = ['_DATABASE_URL', '_TOKEN', '_PRIVATE_KEY', '_HANDOFF_KEY', '_DEPLOY_KEY', '_SECRET_ACCESS_KEY', '_APPLICATION_KEY'];
/** Runner-provided, non-secret or runner-owned variables that merely look credential-shaped. */
const RUNNER_ALLOWED = new Set(['ACTIONS_RUNTIME_TOKEN', 'ACTIONS_CACHE_URL', 'ACTIONS_RESULTS_URL']);

export function isCredentialName(name: string): boolean {
  const upper = name.toUpperCase();
  if (RUNNER_ALLOWED.has(upper)) return false;
  return CREDENTIAL_EXACT.has(upper)
    || CREDENTIAL_PREFIXES.some((prefix) => upper.startsWith(prefix))
    || CREDENTIAL_SUFFIXES.some((suffix) => upper.endsWith(suffix));
}

/** Throws naming (never echoing) any missing or foreign credential variable. */
export function checkJobEnv(kind: JobKind, env: NodeJS.ProcessEnv): void {
  const required = JOB_ENV[kind];
  const present = (name: string): boolean => typeof env[name] === 'string' && env[name]!.trim() !== '';
  const foreign = Object.keys(env).filter((name) => present(name) && isCredentialName(name) && !required.includes(name)).sort();
  if (foreign.length > 0) throw new FailClosedError(`${kind} must not hold: ${foreign.join(', ')}`);
  const missing = required.filter((name) => !present(name));
  if (missing.length > 0) throw new FailClosedError(`${kind} requires: ${missing.join(', ')}`);
}

export function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (typeof value !== 'string' || value.trim() === '') throw new FailClosedError(`${name} is required`);
  return value;
}
