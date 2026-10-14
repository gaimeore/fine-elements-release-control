/**
 * Rendition placement: the trusted control plane, not the sandbox, puts
 * every publication rendition into the built bundle, at the same public
 * paths the private build references (images/collections/<id>/<file> and
 * images/site/<file>), and only after the bytes' SHA-256 equals the hash
 * carried in the immutable snapshot's filename.
 *
 * Contract with the private build (verified byte-for-byte at RC1P and again
 * at RC9): file = `<uuid>-<64 hex>.webp`; rendition object keys are
 * `renditions/<collectionId>/<photographId>/web-<hash>.webp` and
 * `renditions/site/<siteImageId>/web-<hash>.webp`.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { FailClosedError } from '../lib/errors.ts';

export interface RenditionPlacement {
  readonly kind: 'collection' | 'site';
  readonly publicPath: string;
  readonly renditionKey: string;
  readonly sha256: string;
}

const FILE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-([0-9a-f]{64})\.webp$/;
const COLLECTION_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new FailClosedError(`snapshot ${label} must be an object`);
  return value as Record<string, unknown>;
}

/** Placements in snapshot sequence; the private build re-validates everything else. */
export function placementsFromSnapshot(bytes: Uint8Array): RenditionPlacement[] {
  let body: Record<string, unknown>;
  try { body = asObject(JSON.parse(Buffer.from(bytes).toString('utf8')), 'root'); } catch (error) {
    if (error instanceof FailClosedError) throw error;
    throw new FailClosedError('snapshot is not valid JSON');
  }
  if (body.schemaVersion !== 1 && body.schemaVersion !== 2) throw new FailClosedError('snapshot schemaVersion must be 1 or 2');
  const placements: RenditionPlacement[] = [];
  for (const [collectionId, entries] of Object.entries(asObject(body.collections, 'collections'))) {
    if (!COLLECTION_ID.test(collectionId) || !Array.isArray(entries)) throw new FailClosedError('snapshot collection is malformed');
    for (const entry of entries) {
      const file = asObject(entry, 'entry').file;
      const match = typeof file === 'string' ? FILE.exec(file) : null;
      if (match === null) throw new FailClosedError('snapshot entry filename is malformed');
      placements.push({
        kind: 'collection',
        publicPath: `images/collections/${collectionId}/${file as string}`,
        renditionKey: `renditions/${collectionId}/${match[1]}/web-${match[2]}.webp`,
        sha256: match[2]!,
      });
    }
  }
  if (body.schemaVersion === 2) {
    const homepage = asObject(body.homepage, 'homepage');
    if (homepage.aboutPortrait !== undefined) {
      const file = asObject(homepage.aboutPortrait, 'aboutPortrait').file;
      const match = typeof file === 'string' ? FILE.exec(file) : null;
      if (match === null) throw new FailClosedError('snapshot portrait filename is malformed');
      placements.push({
        kind: 'site',
        publicPath: `images/site/${file as string}`,
        renditionKey: `renditions/site/${match[1]}/web-${match[2]}.webp`,
        sha256: match[2]!,
      });
    }
  }
  if (new Set(placements.map((p) => p.publicPath)).size !== placements.length) throw new FailClosedError('snapshot repeats a rendition path');
  return placements;
}

/**
 * Placements public before and absent now, compared by exact public path.
 * The filename carries the photograph/site-image id AND the content hash, so
 * an unchanged, reordered or metadata-only entry keeps its path, while a
 * replacement, move, archive or portrait change retires the old path.
 */
export function removedPlacements(before: readonly RenditionPlacement[], after: readonly RenditionPlacement[]): RenditionPlacement[] {
  const kept = new Set(after.map((placement) => placement.publicPath));
  return before.filter((placement) => !kept.has(placement.publicPath));
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Writes each verified rendition into the unpacked bundle; never overwrites. */
export function injectRenditions(bundleRoot: string, placements: readonly RenditionPlacement[], renditions: ReadonlyMap<string, Uint8Array>): void {
  for (const placement of placements) {
    const bytes = renditions.get(placement.renditionKey);
    if (bytes === undefined) throw new FailClosedError('a rendition is missing from the prepared inputs');
    if (sha256Hex(bytes) !== placement.sha256) throw new FailClosedError('a rendition does not match its snapshot hash');
    const target = path.join(bundleRoot, ...placement.publicPath.split('/'));
    if (existsSync(target)) throw new FailClosedError('a rendition path already exists in the bundle');
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, bytes, { flag: 'wx', mode: 0o644 });
  }
}
