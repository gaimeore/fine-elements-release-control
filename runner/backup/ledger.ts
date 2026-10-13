/**
 * master_backup persistence for the backup lane (migration 0011 in the
 * private source repository is the schema authority; this mirrors it).
 * Append-only: INSERT and SELECT only. The backup-verifier role is granted
 * exactly SELECT(master_key, content_hash, master_bytes) on photograph and
 * site_image, and SELECT/INSERT on master_backup.
 */
import {
  readEnum,
  readNullableSafeInteger,
  readNullableString,
  readSafeInteger,
  readString,
  readTimestamp,
  type RawRow,
  type SqlExecutor,
} from '../lib/db.ts';

export type MasterBackupState = 'verified' | 'mismatch';
export const MASTER_BACKUP_STATES: readonly MasterBackupState[] = ['verified', 'mismatch'];

/** One row of master_backup. Its identity is (masterKey, b2VersionId). */
export interface MasterBackupRecord {
  masterKey: string;
  b2VersionId: string;
  state: MasterBackupState;
  sourceSha256: string;
  sourceBytes: number;
  observedSha256: string | null;
  observedBytes: number | null;
  recordedAt: string;
}

export type NewMasterBackup = Omit<MasterBackupRecord, 'recordedAt'>;

/** The authoritative master a proof must match (photograph / site_image row). */
export interface AuthoritativeMaster {
  readonly masterKey: string;
  readonly contentHash: string;
  readonly masterBytes: number;
}

export interface MasterBackupProof {
  readonly masterKey: string;
  readonly sourceSha256: string;
  readonly sourceBytes: number;
}

/**
 * A proof exists exactly when the record is a 'verified' row for the same
 * master whose source SHA-256 and byte count equal the authoritative master.
 */
export function deriveMasterBackupProof(record: MasterBackupRecord, master: AuthoritativeMaster): MasterBackupProof | null {
  if (record.state !== 'verified') return null;
  if (record.masterKey !== master.masterKey) return null;
  if (record.sourceSha256 !== master.contentHash) return null;
  if (record.sourceBytes !== master.masterBytes) return null;
  return { masterKey: record.masterKey, sourceSha256: record.sourceSha256, sourceBytes: record.sourceBytes };
}

const COLUMNS = 'master_key, b2_version_id, state, source_sha256, source_bytes, observed_sha256, observed_bytes, recorded_at';

function mapRow(row: RawRow): MasterBackupRecord {
  return {
    masterKey: readString(row, 'master_key'),
    b2VersionId: readString(row, 'b2_version_id'),
    state: readEnum(row, 'state', MASTER_BACKUP_STATES),
    sourceSha256: readString(row, 'source_sha256'),
    sourceBytes: readSafeInteger(row, 'source_bytes'),
    observedSha256: readNullableString(row, 'observed_sha256'),
    observedBytes: readNullableSafeInteger(row, 'observed_bytes'),
    recordedAt: readTimestamp(row, 'recorded_at'),
  };
}

export async function insertMasterBackup(executor: SqlExecutor, backup: NewMasterBackup): Promise<MasterBackupRecord> {
  const result = await executor.query(
    `INSERT INTO master_backup (master_key, b2_version_id, state, source_sha256, source_bytes, observed_sha256, observed_bytes)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING ${COLUMNS}`,
    [backup.masterKey, backup.b2VersionId, backup.state, backup.sourceSha256, backup.sourceBytes, backup.observedSha256, backup.observedBytes],
  );
  const row = result.rows[0];
  if (row === undefined) throw new Error('insertMasterBackup: INSERT ... RETURNING produced no row');
  return mapRow(row);
}

/** Every recorded observation of one master, oldest first. */
export async function listMasterBackups(executor: SqlExecutor, masterKey: string): Promise<MasterBackupRecord[]> {
  const result = await executor.query(
    `SELECT ${COLUMNS} FROM master_backup WHERE master_key = $1 ORDER BY recorded_at, b2_version_id`,
    [masterKey],
  );
  return result.rows.map(mapRow);
}

const AUTHORITATIVE_MASTER_SQL =
  `SELECT master_key, content_hash, master_bytes FROM photograph
   UNION ALL
   SELECT master_key, content_hash, master_bytes FROM site_image`;

function mapMaster(row: RawRow): AuthoritativeMaster {
  return {
    masterKey: readString(row, 'master_key'),
    contentHash: readString(row, 'content_hash'),
    masterBytes: readSafeInteger(row, 'master_bytes'),
  };
}

export async function listAuthoritativeMasters(executor: SqlExecutor): Promise<AuthoritativeMaster[]> {
  const result = await executor.query(`SELECT master_key, content_hash, master_bytes FROM (${AUTHORITATIVE_MASTER_SQL}) AS authoritative ORDER BY master_key`);
  return result.rows.map(mapMaster);
}

/** More than one row for a key is a conflict the caller must refuse, never resolve. */
export async function findAuthoritativeMasters(executor: SqlExecutor, masterKey: string): Promise<AuthoritativeMaster[]> {
  const result = await executor.query(
    `SELECT master_key, content_hash, master_bytes FROM (${AUTHORITATIVE_MASTER_SQL}) AS authoritative WHERE master_key = $1`,
    [masterKey],
  );
  return result.rows.map(mapMaster);
}
