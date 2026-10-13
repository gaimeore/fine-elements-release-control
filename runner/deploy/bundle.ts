/**
 * The sandbox build output is DATA ONLY: validated, packed deterministically,
 * re-validated after unpacking, and uploaded as static assets. Nothing here
 * (or anywhere in the deploy runner) imports or executes a bundle file.
 */
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { FailClosedError } from '../lib/errors.ts';
import { assertSafeRelativePath } from '../lib/tar.ts';

export const BUNDLE_LIMITS = { maxFiles: 20_000, maxBytes: 512 * 1024 * 1024, maxPathLength: 255 } as const;
export const ALLOWED_EXTENSIONS = new Set([
  'html', 'js', 'mjs', 'css', 'svg', 'webp', 'jpg', 'jpeg', 'png', 'gif', 'avif', 'ico',
  'woff', 'woff2', 'ttf', 'otf', 'txt', 'xml', 'webmanifest',
]);
/** Files with no extension that are allowed, by exact path. */
const ALLOWED_BARE = new Set(['_headers']);
const FORBIDDEN_NAMES = new Set(['_worker.js', '_routes.json', '.assetsignore', 'package.json', 'package-lock.json']);
const FORBIDDEN_TOP = new Set(['server', 'src', 'node_modules', 'worker']);
export const RENDITION_DIRECTORIES = ['images/collections', 'images/site'] as const;

export interface BundleFile {
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
}

export function assertBundlePath(relative: string): void {
  assertSafeRelativePath(relative);
  if (relative.length > BUNDLE_LIMITS.maxPathLength) throw new FailClosedError('bundle path is too long');
  const segments = relative.split('/');
  const name = segments.at(-1)!;
  if (FORBIDDEN_TOP.has(segments[0]!)) throw new FailClosedError('bundle contains application source paths');
  if (segments.some((segment) => segment.startsWith('.git') || segment === 'node_modules')) throw new FailClosedError('bundle contains repository metadata');
  if (FORBIDDEN_NAMES.has(name)) throw new FailClosedError('bundle contains a forbidden file');
  if (name.endsWith('.map')) throw new FailClosedError('bundle contains a source map');
  const dot = name.lastIndexOf('.');
  if (dot <= 0) {
    if (!ALLOWED_BARE.has(relative)) throw new FailClosedError('bundle contains a file without an allowed extension');
  } else if (!ALLOWED_EXTENSIONS.has(name.slice(dot + 1))) {
    throw new FailClosedError('bundle contains an unexpected file type');
  }
}

export function isRenditionPath(relative: string): boolean {
  return RENDITION_DIRECTORIES.some((dir) => relative === dir || relative.startsWith(`${dir}/`));
}

/**
 * Walks a built tree with lstat: regular files and directories only (no
 * symlinks, hardlinks or devices), every path checked, limits enforced.
 * `renditions: 'forbidden'` is the sandbox-output rule; the post-injection
 * check passes `'allowed'`.
 */
export function validateBundleTree(root: string, renditions: 'forbidden' | 'allowed'): BundleFile[] {
  const files: BundleFile[] = [];
  let total = 0;
  const walk = (relative: string): void => {
    for (const name of readdirSync(path.join(root, relative)).sort()) {
      const rel = relative === '' ? name : `${relative}/${name}`;
      const info = lstatSync(path.join(root, rel));
      if (info.isSymbolicLink()) throw new FailClosedError('bundle contains a symbolic link');
      if (info.isDirectory()) { walk(rel); continue; }
      if (!info.isFile()) throw new FailClosedError('bundle contains a special file');
      if (info.nlink > 1) throw new FailClosedError('bundle contains a hard link');
      assertBundlePath(rel);
      if (renditions === 'forbidden' && isRenditionPath(rel)) throw new FailClosedError('sandbox bundle contains rendition bytes');
      const bytes = readFileSync(path.join(root, rel));
      total += bytes.length;
      files.push({ path: rel, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
      if (files.length > BUNDLE_LIMITS.maxFiles || total > BUNDLE_LIMITS.maxBytes) throw new FailClosedError('bundle exceeds its file-count or size limit');
    }
  };
  walk('');
  if (!files.some((file) => file.path === '_headers')) throw new FailClosedError('bundle is missing _headers');
  if (!files.some((file) => file.path === 'index.html')) throw new FailClosedError('bundle is missing index.html');
  return files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

const MAGIC = Buffer.from('FEBUNDLE/1\n', 'utf8');

/** Deterministic: sorted paths, no timestamps, no modes. */
export function packBundle(root: string, files: readonly BundleFile[]): Buffer {
  const header = Buffer.from(JSON.stringify({ files }), 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(header.length, 0);
  return Buffer.concat([MAGIC, length, header, ...files.map((file) => readFileSync(path.join(root, ...file.path.split('/'))))]);
}

/** Unpacks into an EMPTY directory, re-checking every path, size and digest. */
export function unpackBundle(packed: Buffer, destination: string): BundleFile[] {
  if (!packed.subarray(0, MAGIC.length).equals(MAGIC)) throw new FailClosedError('bundle format is not FEBUNDLE/1');
  const headerLength = packed.readUInt32BE(MAGIC.length);
  let offset = MAGIC.length + 4 + headerLength;
  let parsed: unknown;
  try { parsed = JSON.parse(packed.subarray(MAGIC.length + 4, offset).toString('utf8')); } catch { throw new FailClosedError('bundle header is malformed'); }
  const files = (parsed as { files?: unknown }).files;
  if (!Array.isArray(files) || files.length > BUNDLE_LIMITS.maxFiles) throw new FailClosedError('bundle header is malformed');
  if (readdirSync(destination).length > 0) throw new FailClosedError('bundle destination must be empty');
  const seen = new Set<string>();
  for (const raw of files as BundleFile[]) {
    if (typeof raw.path !== 'string' || !Number.isSafeInteger(raw.size) || raw.size < 0 || typeof raw.sha256 !== 'string') throw new FailClosedError('bundle header entry is malformed');
    assertBundlePath(raw.path);
    if (seen.has(raw.path)) throw new FailClosedError('bundle header repeats a path');
    seen.add(raw.path);
    const bytes = packed.subarray(offset, offset + raw.size);
    if (bytes.length !== raw.size || createHash('sha256').update(bytes).digest('hex') !== raw.sha256) throw new FailClosedError('bundle content does not match its header');
    offset += raw.size;
    const target = path.join(destination, ...raw.path.split('/'));
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, bytes, { flag: 'wx', mode: 0o644 });
  }
  if (offset !== packed.length) throw new FailClosedError('bundle has trailing bytes');
  return files as BundleFile[];
}
