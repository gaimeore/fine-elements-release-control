/**
 * Release manifests (fine-elements-release-manifest/1): release/test.json and
 * release/prod.json on the protected production-release branch. The only
 * way a private source commit becomes deployable. Never "latest main".
 */
import { FailClosedError } from './errors.ts';
import type { Target } from './target-config.ts';

export const MANIFEST_SCHEMA = 'fine-elements-release-manifest/1';
export const SOURCE_REPOSITORY = 'gaimeore/fine-elements';

export interface ReleaseManifest {
  readonly schema: typeof MANIFEST_SCHEMA;
  readonly target: Target;
  readonly sequence: number;
  readonly source_repository: typeof SOURCE_REPOSITORY;
  readonly source_commit: string;
  readonly source_archive_sha256: string;
  readonly previous_source_commit: string | null;
  readonly migration_ceiling: string;
  /** PROD only: the TEST sequence whose exact source this promotes. */
  readonly promoted_from_test_sequence?: number;
}

const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const CEILING = /^\d{4}_[a-z0-9_]+$/;

export function parseManifest(json: unknown, expectedTarget?: Target): ReleaseManifest {
  if (typeof json !== 'object' || json === null || Array.isArray(json)) throw new FailClosedError('manifest must be an object');
  const raw = json as Record<string, unknown>;
  const target = raw.target;
  if (target !== 'test' && target !== 'prod') throw new FailClosedError('manifest target must be test or prod');
  if (expectedTarget !== undefined && target !== expectedTarget) throw new FailClosedError(`manifest target must be ${expectedTarget}`);
  const expectedKeys = ['schema', 'target', 'sequence', 'source_repository', 'source_commit', 'source_archive_sha256', 'previous_source_commit', 'migration_ceiling',
    ...(target === 'prod' ? ['promoted_from_test_sequence'] : [])];
  const keys = Object.keys(raw);
  if (keys.length !== expectedKeys.length || !expectedKeys.every((key) => keys.includes(key))) throw new FailClosedError('manifest fields are not exactly the schema');
  if (raw.schema !== MANIFEST_SCHEMA) throw new FailClosedError('manifest schema is not fine-elements-release-manifest/1');
  if (!Number.isSafeInteger(raw.sequence) || (raw.sequence as number) < 1) throw new FailClosedError('manifest sequence must be a positive integer');
  if (raw.source_repository !== SOURCE_REPOSITORY) throw new FailClosedError('manifest source_repository is not the private source repository');
  if (typeof raw.source_commit !== 'string' || !SHA1.test(raw.source_commit)) throw new FailClosedError('manifest source_commit must be 40 lowercase hex');
  if (typeof raw.source_archive_sha256 !== 'string' || !SHA256.test(raw.source_archive_sha256)) throw new FailClosedError('manifest source_archive_sha256 must be 64 lowercase hex');
  if (typeof raw.migration_ceiling !== 'string' || !CEILING.test(raw.migration_ceiling)) throw new FailClosedError('manifest migration_ceiling is malformed');
  const previous = raw.previous_source_commit;
  if (raw.sequence === 1) {
    if (previous !== null) throw new FailClosedError('manifest sequence 1 has no previous_source_commit');
  } else if (typeof previous !== 'string' || !SHA1.test(previous)) {
    throw new FailClosedError('manifest previous_source_commit must be 40 lowercase hex');
  }
  if (previous === raw.source_commit) throw new FailClosedError('manifest source_commit must differ from previous_source_commit');
  if (target === 'prod' && (!Number.isSafeInteger(raw.promoted_from_test_sequence) || (raw.promoted_from_test_sequence as number) < 1)) {
    throw new FailClosedError('prod manifest promoted_from_test_sequence must be a positive integer');
  }
  return raw as unknown as ReleaseManifest;
}

/** Chain rule between the accepted manifest (or none) and its successor. */
export function validateManifestSuccessor(previous: ReleaseManifest | null, next: ReleaseManifest): void {
  if (previous === null) {
    if (next.sequence !== 1) throw new FailClosedError('the first manifest must have sequence 1');
    return;
  }
  if (previous.target !== next.target) throw new FailClosedError('manifest target cannot change');
  if (next.sequence !== previous.sequence + 1) throw new FailClosedError('manifest sequence must increase by exactly 1');
  if (next.previous_source_commit !== previous.source_commit) throw new FailClosedError('previous_source_commit must equal the accepted source_commit');
}

/** A whole history (oldest first) must be an unbroken chain. */
export function validateManifestHistory(history: readonly ReleaseManifest[]): void {
  let previous: ReleaseManifest | null = null;
  for (const manifest of history) {
    validateManifestSuccessor(previous, manifest);
    previous = manifest;
  }
}

/**
 * PROD may deploy only a source TEST had: the TEST manifest with sequence
 * promoted_from_test_sequence must name the same commit, archive and ceiling.
 */
export function validateProdPromotion(prod: ReleaseManifest, testHistory: readonly ReleaseManifest[]): void {
  if (prod.target !== 'prod') throw new FailClosedError('promotion check applies to prod manifests');
  const tested = testHistory.find((manifest) => manifest.sequence === prod.promoted_from_test_sequence);
  if (tested === undefined) throw new FailClosedError('promoted_from_test_sequence is not in the TEST history');
  if (tested.source_commit !== prod.source_commit
    || tested.source_archive_sha256 !== prod.source_archive_sha256
    || tested.migration_ceiling !== prod.migration_ceiling) {
    throw new FailClosedError('prod manifest does not match the promoted TEST manifest');
  }
}
