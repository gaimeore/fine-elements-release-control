/**
 * A strict reader for the `git archive --format=tar` stream. Only regular
 * files and directories are accepted (plus git's pax headers); links,
 * devices, absolute or `..` paths fail closed. Entries are data only.
 */
import { FailClosedError } from './errors.ts';

export interface TarEntry {
  readonly path: string;
  readonly type: 'file' | 'dir';
  readonly data: Buffer;
}

function field(header: Buffer, start: number, length: number): string {
  const raw = header.subarray(start, start + length);
  const end = raw.indexOf(0);
  return raw.subarray(0, end === -1 ? length : end).toString('utf8');
}

function octal(header: Buffer, start: number, length: number): number {
  const text = field(header, start, length).trim();
  if (!/^[0-7]*$/.test(text)) throw new FailClosedError('tar header number is malformed');
  return text === '' ? 0 : parseInt(text, 8);
}

function paxPath(data: Buffer): string | null {
  let offset = 0;
  let path: string | null = null;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) break;
    const length = Number(data.subarray(offset, space).toString('utf8'));
    if (!Number.isSafeInteger(length) || length <= 0) throw new FailClosedError('tar pax record is malformed');
    const record = data.subarray(space + 1, offset + length - 1).toString('utf8');
    const eq = record.indexOf('=');
    if (record.slice(0, eq) === 'path') path = record.slice(eq + 1);
    offset += length;
  }
  return path;
}

export function assertSafeRelativePath(path: string): void {
  if (path === '' || path.length > 4096 || path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.includes('\\') || path.includes('\0')) {
    throw new FailClosedError('archive path is not a safe relative path');
  }
  for (const segment of path.split('/')) {
    if (segment === '..' || segment === '.') throw new FailClosedError('archive path is not a safe relative path');
  }
}

export function readTar(archive: Buffer): TarEntry[] {
  const entries: TarEntry[] = [];
  let offset = 0;
  let pendingPath: string | null = null;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const size = octal(header, 124, 12);
    const type = String.fromCharCode(header[156]!);
    const dataStart = offset + 512;
    const data = archive.subarray(dataStart, dataStart + size);
    if (data.length !== size) throw new FailClosedError('tar entry is truncated');
    offset = dataStart + Math.ceil(size / 512) * 512;
    if (type === 'g') continue; // git's global pax header (commit id comment)
    if (type === 'x') { pendingPath = paxPath(data); continue; }
    const prefix = field(header, 345, 155);
    const name = pendingPath ?? (prefix === '' ? field(header, 0, 100) : `${prefix}/${field(header, 0, 100)}`);
    pendingPath = null;
    const clean = name.endsWith('/') ? name.slice(0, -1) : name;
    assertSafeRelativePath(clean);
    if (type === '0' || type === '\0') entries.push({ path: clean, type: 'file', data: Buffer.from(data) });
    else if (type === '5') entries.push({ path: clean, type: 'dir', data: Buffer.alloc(0) });
    else throw new FailClosedError('archive contains a link or special entry');
  }
  return entries;
}
