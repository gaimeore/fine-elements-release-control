/**
 * config/recipients.json: the committed X25519 PUBLIC keys of each
 * environment that opens handoffs. null until its RC gate provisions the
 * environment; a null recipient fails closed.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { FailClosedError } from './errors.ts';
import { handoffDigest, openHandoff, privateKeyFromJwk, sealHandoff, type HandoffContext, type RecipientPublicKey } from './handoff.ts';
import type { Target } from './target-config.ts';

export type RecipientRole = 'backup-verify' | 'backup-write' | 'build' | 'deploy' | 'verify' | 'audit';
export const RECIPIENT_ROLES: readonly RecipientRole[] = ['backup-verify', 'backup-write', 'build', 'deploy', 'verify', 'audit'];

export type RecipientTable = Readonly<Record<Target, Readonly<Record<RecipientRole, string | null>>>>;

export function parseRecipientTable(json: unknown): RecipientTable {
  const raw = json as { schema?: unknown; recipients?: Record<string, Record<string, unknown>> };
  if (typeof raw !== 'object' || raw === null || raw.schema !== 'fe-recipients/1' || typeof raw.recipients !== 'object' || raw.recipients === null) {
    throw new FailClosedError('recipient table is malformed');
  }
  if (Object.keys(raw).sort().join(',') !== 'recipients,schema' || Object.keys(raw.recipients).sort().join(',') !== 'prod,test') {
    throw new FailClosedError('recipient table must list exactly test and prod');
  }
  const seen = new Set<string>();
  for (const target of ['test', 'prod'] as const) {
    const row = raw.recipients[target];
    if (typeof row !== 'object' || row === null || Object.keys(row).sort().join(',') !== [...RECIPIENT_ROLES].sort().join(',')) {
      throw new FailClosedError(`recipient row ${target} must list exactly the recipient roles`);
    }
    for (const role of RECIPIENT_ROLES) {
      const value = row[role];
      if (value !== null && (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value))) throw new FailClosedError(`recipient ${target}/${role} is malformed`);
      if (typeof value === 'string') {
        if (seen.has(value)) throw new FailClosedError('recipient keys must be distinct');
        seen.add(value);
      }
    }
  }
  return raw.recipients as unknown as RecipientTable;
}

export function loadRecipientTable(file = 'config/recipients.json'): RecipientTable {
  return parseRecipientTable(JSON.parse(readFileSync(file, 'utf8')) as unknown);
}

export function recipientsFor(table: RecipientTable, target: Target, roles: readonly RecipientRole[]): RecipientPublicKey[] {
  return roles.map((role) => {
    const x = table[target][role];
    if (x === null) throw new FailClosedError(`recipient ${target}/${role} is not provisioned`);
    return { name: `${target}/${role}`, x };
  });
}

/** Seals and writes a handoff file; returns the digest for the producer's job output. */
export function writeHandoff(file: string, plaintext: Buffer, recipients: readonly RecipientPublicKey[], context: HandoffContext): string {
  const envelope = sealHandoff(plaintext, recipients, context);
  writeFileSync(path.resolve(file), envelope);
  return handoffDigest(envelope);
}

export function readHandoff(file: string, expectedDigest: string | undefined, privateJwk: string, context: HandoffContext): Buffer {
  if (expectedDigest === undefined) throw new FailClosedError('expected handoff digest is required');
  return openHandoff(readFileSync(path.resolve(file)), expectedDigest, privateKeyFromJwk(privateJwk), context);
}
