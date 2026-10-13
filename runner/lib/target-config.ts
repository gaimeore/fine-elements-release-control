/**
 * TARGET_CONFIG_JSON: the non-credential operational identifiers of one
 * environment (server/ARCHITECTURE.md §19 "Target configuration").
 *
 * Exact schema per environment kind, a `target` that must equal the
 * workflow's hard-coded target, and a random `salt`, so the committed
 * fingerprint (SHA-256 of the canonical JSON) cannot be dictionary-guessed.
 * Every runner verifies the fingerprint BEFORE any network call. Credentials
 * never belong here.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { canonicalJson } from './canonical-json.ts';
import { FailClosedError } from './errors.ts';

export type Target = 'test' | 'prod';
export const TARGETS: readonly Target[] = ['test', 'prod'];

export type ConfigKind = 'backup-verify' | 'backup-write' | 'deploy-prepare' | 'deploy' | 'verify' | 'control-policy';
export const CONFIG_KINDS: readonly ConfigKind[] = ['backup-verify', 'backup-write', 'deploy-prepare', 'deploy', 'verify', 'control-policy'];

const NEON_ID = /^[a-z0-9][a-z0-9-]{2,62}$/;
const NAME = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const FIELD_RULES: Readonly<Record<string, RegExp>> = {
  neon_project_id: NEON_ID,
  neon_branch_id: NEON_ID,
  neon_database: /^[a-z_][a-z0-9_]{0,62}$/,
  b2_bucket: NAME,
  b2_endpoint: /^https:\/\/[a-z0-9.-]+$/,
  b2_region: /^[a-z0-9-]{2,40}$/,
  destination_prefix: /^r2\/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\/$/,
  cloudflare_account_id: /^[0-9a-f]{32}$/,
  r2_source_bucket: NAME,
  r2_private_media_bucket: NAME,
  deployment_environment_label: /^[a-z][a-z0-9-]{1,30}$/,
  public_worker_name: /^[a-z0-9][a-z0-9-]{1,62}$/,
  public_origin: /^https:\/\/[a-z0-9.-]+$/,
  policy_app_id: /^[1-9][0-9]{0,11}$/,
  policy_app_installation_id: /^[1-9][0-9]{0,15}$/,
};

const DB = ['neon_project_id', 'neon_branch_id', 'neon_database'];
export const CONFIG_FIELDS: Readonly<Record<ConfigKind, readonly string[]>> = {
  'backup-verify': [...DB, 'b2_bucket', 'b2_endpoint', 'b2_region', 'destination_prefix'],
  'backup-write': ['cloudflare_account_id', 'r2_source_bucket', 'b2_bucket', 'b2_endpoint', 'b2_region', 'destination_prefix'],
  'deploy-prepare': [...DB, 'cloudflare_account_id', 'r2_private_media_bucket', 'deployment_environment_label'],
  deploy: [...DB, 'cloudflare_account_id', 'public_worker_name', 'deployment_environment_label'],
  verify: [...DB, 'cloudflare_account_id', 'public_worker_name', 'public_origin', 'deployment_environment_label'],
  'control-policy': ['policy_app_id', 'policy_app_installation_id'],
};

export const TARGET_CONFIG_SCHEMA = 'fe-target-config/1';

export interface TargetConfig {
  readonly schema: typeof TARGET_CONFIG_SCHEMA;
  readonly kind: ConfigKind;
  readonly target: Target;
  readonly salt: string;
  readonly fields: Readonly<Record<string, string>>;
}

/** Parses exactly; never echoes a value in an error. */
export function parseTargetConfig(json: string, kind: ConfigKind, target: Target): TargetConfig {
  let raw: unknown;
  try { raw = JSON.parse(json); } catch { throw new FailClosedError('TARGET_CONFIG_JSON is not valid JSON'); }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new FailClosedError('TARGET_CONFIG_JSON must be an object');
  const record = raw as Record<string, unknown>;
  const expected = ['schema', 'kind', 'target', 'salt', ...CONFIG_FIELDS[kind]];
  const keys = Object.keys(record);
  const unknown = keys.filter((key) => !expected.includes(key));
  const missing = expected.filter((key) => !keys.includes(key));
  if (unknown.length > 0) throw new FailClosedError(`TARGET_CONFIG_JSON has unknown fields: ${unknown.join(', ')}`);
  if (missing.length > 0) throw new FailClosedError(`TARGET_CONFIG_JSON is missing fields: ${missing.join(', ')}`);
  if (record.schema !== TARGET_CONFIG_SCHEMA) throw new FailClosedError('TARGET_CONFIG_JSON schema is not fe-target-config/1');
  if (record.kind !== kind) throw new FailClosedError(`TARGET_CONFIG_JSON is not a ${kind} config`);
  if (record.target !== target) throw new FailClosedError(`TARGET_CONFIG_JSON is not a ${target} config`);
  if (typeof record.salt !== 'string' || !/^[0-9a-f]{64}$/.test(record.salt)) throw new FailClosedError('TARGET_CONFIG_JSON salt must be 64 lowercase hex');
  const fields: Record<string, string> = {};
  for (const field of CONFIG_FIELDS[kind]) {
    const value = record[field];
    if (typeof value !== 'string' || !FIELD_RULES[field]!.test(value)) throw new FailClosedError(`TARGET_CONFIG_JSON field ${field} is malformed`);
    fields[field] = value;
  }
  if (kind === 'backup-write' && fields.destination_prefix !== `r2/${fields.r2_source_bucket}/`) {
    throw new FailClosedError('TARGET_CONFIG_JSON destination_prefix must be r2/<r2_source_bucket>/');
  }
  return { schema: TARGET_CONFIG_SCHEMA, kind, target, salt: record.salt, fields };
}

/** SHA-256 of the canonical JSON of the whole config (salt included). */
export function targetConfigFingerprint(config: TargetConfig): string {
  const body: Record<string, string> = { schema: config.schema, kind: config.kind, target: config.target, salt: config.salt, ...config.fields };
  return createHash('sha256').update(canonicalJson(body), 'utf8').digest('hex');
}

export type FingerprintTable = Readonly<Record<Target, Readonly<Record<ConfigKind, string | null>>>>;

export function parseFingerprintTable(json: unknown): FingerprintTable {
  const raw = json as { schema?: unknown; fingerprints?: Record<string, Record<string, unknown>> };
  if (typeof raw !== 'object' || raw === null || raw.schema !== 'fe-target-fingerprints/1' || typeof raw.fingerprints !== 'object' || raw.fingerprints === null) {
    throw new FailClosedError('target fingerprint table is malformed');
  }
  if (Object.keys(raw).sort().join(',') !== 'fingerprints,schema') throw new FailClosedError('target fingerprint table has unknown fields');
  if (Object.keys(raw.fingerprints).sort().join(',') !== 'prod,test') throw new FailClosedError('target fingerprint table must list exactly test and prod');
  const seen = new Set<string>();
  for (const target of TARGETS) {
    const row = raw.fingerprints[target];
    if (typeof row !== 'object' || row === null || Object.keys(row).sort().join(',') !== [...CONFIG_KINDS].sort().join(',')) {
      throw new FailClosedError(`target fingerprint table row ${target} must list exactly the config kinds`);
    }
    for (const kind of CONFIG_KINDS) {
      const value = row[kind];
      if (value !== null && (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))) throw new FailClosedError(`fingerprint ${target}/${kind} is malformed`);
      if (typeof value === 'string') {
        if (seen.has(value)) throw new FailClosedError('fingerprints must be distinct across targets and kinds');
        seen.add(value);
      }
    }
  }
  return raw.fingerprints as unknown as FingerprintTable;
}

export function loadFingerprintTable(path = 'config/target-fingerprints.json'): FingerprintTable {
  return parseFingerprintTable(JSON.parse(readFileSync(path, 'utf8')) as unknown);
}

/**
 * Parse + fingerprint + compare. Fails closed when no fingerprint has been
 * accepted for this target/kind yet (all null until RC6).
 */
export function verifiedTargetConfig(
  json: string | undefined,
  kind: ConfigKind,
  target: Target,
  table: FingerprintTable = loadFingerprintTable(),
): TargetConfig {
  if (json === undefined || json.trim() === '') throw new FailClosedError('TARGET_CONFIG_JSON is required');
  const config = parseTargetConfig(json, kind, target);
  const expected = table[target][kind];
  if (expected === null) throw new FailClosedError(`no accepted target fingerprint for ${target}/${kind}`);
  if (targetConfigFingerprint(config) !== expected) throw new FailClosedError(`target config fingerprint mismatch for ${target}/${kind}`);
  return config;
}

export function parseTarget(value: string | undefined): Target {
  if (value !== 'test' && value !== 'prod') throw new FailClosedError('target must be exactly test or prod');
  return value;
}
