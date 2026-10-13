/**
 * Deterministic JSON: object keys sorted (code-unit order), no whitespace,
 * finite numbers only. Used for fingerprints and handoff AAD, where the same
 * logical value must always produce the same bytes.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON refuses non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('canonical JSON accepts plain objects only');
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => {
      if (record[key] === undefined) throw new TypeError(`canonical JSON refuses undefined at "${key}"`);
      return `${JSON.stringify(key)}:${canonicalJson(record[key])}`;
    }).join(',')}}`;
  }
  throw new TypeError(`canonical JSON refuses ${typeof value}`);
}
