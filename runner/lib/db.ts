/**
 * Minimal PostgreSQL seam: one pool, explicit transactions, and the live
 * Neon identity check every DB job runs before any mutation.
 */
import pg from 'pg';

import { FailClosedError } from './errors.ts';
import type { TargetConfig } from './target-config.ts';

export type RawRow = Record<string, unknown>;

export interface SqlExecutor {
  query<R extends RawRow = RawRow>(sql: string, params?: readonly unknown[]): Promise<{ rows: R[]; rowCount: number | null }>;
}

export interface SqlDatabase extends SqlExecutor {
  withTransaction<T>(work: (tx: SqlExecutor) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export function createPgDatabase(connectionString: string): SqlDatabase {
  const pool = new pg.Pool({ connectionString, max: 2 });
  return {
    async query(sql, params = []) {
      const result = await pool.query(sql, params as unknown[]);
      return { rows: result.rows, rowCount: result.rowCount };
    },
    async withTransaction(work) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const tx: SqlExecutor = {
          async query(sql, params = []) {
            const result = await client.query(sql, params as unknown[]);
            return { rows: result.rows, rowCount: result.rowCount };
          },
        };
        const value = await work(tx);
        await client.query('COMMIT');
        return value;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },
    async close() {
      await pool.end();
    },
  };
}

/** Refuses to continue unless the live database is exactly the configured target. */
export async function assertDatabaseIdentity(db: SqlExecutor, config: TargetConfig): Promise<void> {
  const result = await db.query(
    `SELECT current_database() AS db,
            current_setting('neon.project_id', true) AS project,
            current_setting('neon.branch_id', true) AS branch`,
  );
  const row = result.rows[0];
  if (row === undefined
    || row.db !== config.fields.neon_database
    || row.project !== config.fields.neon_project_id
    || row.branch !== config.fields.neon_branch_id) {
    throw new FailClosedError('database identity does not match the target configuration');
  }
}

export function readString(row: RawRow, column: string): string {
  const value = row[column];
  if (typeof value !== 'string' || value === '') throw new Error(`column ${column} is not a non-empty string`);
  return value;
}

export function readNullableString(row: RawRow, column: string): string | null {
  const value = row[column];
  if (value === null) return null;
  return readString(row, column);
}

export function readTimestamp(row: RawRow, column: string): string {
  const value = row[column];
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString();
  if (typeof value === 'string' && !Number.isNaN(Date.parse(value))) return new Date(value).toISOString();
  throw new Error(`column ${column} is not a timestamp`);
}

export function readNullableTimestamp(row: RawRow, column: string): string | null {
  return row[column] === null ? null : readTimestamp(row, column);
}

export function readSafeInteger(row: RawRow, column: string): number {
  const value = row[column];
  const parsed = typeof value === 'number' ? value : typeof value === 'string' && /^-?\d+$/.test(value) ? Number(value) : NaN;
  if (!Number.isSafeInteger(parsed)) throw new Error(`column ${column} is not a safe integer`);
  return parsed;
}

export function readNullableSafeInteger(row: RawRow, column: string): number | null {
  return row[column] === null ? null : readSafeInteger(row, column);
}

export function readEnum<T extends string>(row: RawRow, column: string, allowed: readonly T[]): T {
  const value = readString(row, column);
  if (!(allowed as readonly string[]).includes(value)) throw new Error(`column ${column} has an unknown value`);
  return value as T;
}
