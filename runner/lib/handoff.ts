/**
 * Encrypted cross-job handoffs (server/ARCHITECTURE.md §19): artifacts of a
 * public repository are readable by any signed-in user, so every artifact a
 * job hands to another is sealed to the consuming environment's key.
 *
 *   ephemeral X25519 → HKDF-SHA256 → AES-256-GCM (per recipient, wrapping a
 *   random content key) ; AES-256-GCM over the padded payload.
 *
 * The AAD (canonical JSON) binds repository, workflow, target, run id, run
 * attempt, producer job and artifact name (plus deployment bindings where
 * relevant); opening requires the consumer's own expectation of every field.
 * The ciphertext digest is pinned separately through the producer's job
 * output and checked BEFORE decryption.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';

import { canonicalJson } from './canonical-json.ts';
import { FailClosedError } from './errors.ts';

export const HANDOFF_SCHEMA = 'fe-handoff/1';
/** Payloads are padded to whole MiB buckets so artifact size leaks little. */
export const PAD_BUCKET = 1024 * 1024;

export interface HandoffContext {
  readonly repository: string;
  readonly workflowRef: string;
  readonly target: string;
  readonly runId: string;
  readonly runAttempt: string;
  readonly producerJob: string;
  readonly artifact: string;
  /** Deployment bindings (manifest sequence, source commit, attempt id), when relevant. */
  readonly bindings?: Readonly<Record<string, string>>;
}

export interface RecipientPublicKey {
  /** Recipient name, e.g. "test/backup-write". */
  readonly name: string;
  /** Raw X25519 public key, base64url (43 characters). */
  readonly x: string;
}

function aadOf(context: HandoffContext): Buffer {
  for (const [key, value] of Object.entries(context)) {
    if (key !== 'bindings' && (typeof value !== 'string' || value.trim() === '')) throw new FailClosedError(`handoff context ${key} is required`);
  }
  return Buffer.from(canonicalJson({ ...context, bindings: context.bindings ?? {}, schema: HANDOFF_SCHEMA }), 'utf8');
}

export function publicKeyFromX(x: string): KeyObject {
  if (!/^[A-Za-z0-9_-]{43}$/.test(x)) throw new FailClosedError('recipient public key is malformed');
  return createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x }, format: 'jwk' });
}

export function privateKeyFromJwk(json: string): KeyObject {
  let jwk: unknown;
  try { jwk = JSON.parse(json); } catch { throw new FailClosedError('handoff private key is not a JWK'); }
  const record = jwk as Record<string, unknown>;
  if (record.kty !== 'OKP' || record.crv !== 'X25519' || typeof record.d !== 'string' || typeof record.x !== 'string') {
    throw new FailClosedError('handoff private key must be an X25519 JWK');
  }
  return createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d: record.d, x: record.x }, format: 'jwk' });
}

/** A fresh recipient keypair: the private JWK goes to an environment secret, `x` to config/recipients.json. */
export function generateRecipientKeyPair(): { readonly privateJwk: string; readonly x: string } {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const jwk = privateKey.export({ format: 'jwk' }) as { d: string; x: string };
  const x = (publicKey.export({ format: 'jwk' }) as { x: string }).x;
  return { privateJwk: JSON.stringify({ kty: 'OKP', crv: 'X25519', d: jwk.d, x: jwk.x }), x };
}

const rawX = (key: KeyObject): string => (key.export({ format: 'jwk' }) as { x: string }).x;
const kidOf = (x: string): string => createHash('sha256').update(x, 'utf8').digest('hex').slice(0, 32);

function kek(shared: Buffer, ephemeralX: string, recipientX: string, aad: Buffer): Buffer {
  const info = Buffer.concat([Buffer.from(`${HANDOFF_SCHEMA} wrap\n`, 'utf8'), aad]);
  return Buffer.from(hkdfSync('sha256', shared, Buffer.from(`${ephemeralX}.${recipientX}`, 'utf8'), info, 32));
}

function gcmEncrypt(key: Buffer, plaintext: Buffer, aad: Buffer): { iv: Buffer; ciphertext: Buffer; tag: Buffer } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, ciphertext, tag: cipher.getAuthTag() };
}

function gcmDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer, aad: Buffer): Buffer {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new FailClosedError('handoff authentication failed');
  }
}

function pad(plaintext: Buffer): Buffer {
  const total = Math.ceil((plaintext.length + 8) / PAD_BUCKET) * PAD_BUCKET;
  const out = Buffer.alloc(total);
  out.writeBigUInt64BE(BigInt(plaintext.length), 0);
  plaintext.copy(out, 8);
  return out;
}

function unpad(padded: Buffer): Buffer {
  if (padded.length < 8 || padded.length % PAD_BUCKET !== 0) throw new FailClosedError('handoff padding is malformed');
  const length = Number(padded.readBigUInt64BE(0));
  if (length > padded.length - 8) throw new FailClosedError('handoff padding is malformed');
  return padded.subarray(8, 8 + length);
}

const b64 = (buffer: Buffer): string => buffer.toString('base64');
const unb64 = (text: unknown, label: string): Buffer => {
  if (typeof text !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new FailClosedError(`handoff ${label} is malformed`);
  return Buffer.from(text, 'base64');
};

/** Seals `plaintext` to every recipient; returns the envelope bytes. */
export function sealHandoff(plaintext: Buffer, recipients: readonly RecipientPublicKey[], context: HandoffContext): Buffer {
  if (recipients.length === 0) throw new FailClosedError('a handoff needs at least one recipient');
  const aad = aadOf(context);
  const contentKey = randomBytes(32);
  const wrapped = recipients.map((recipient) => {
    const recipientKey = publicKeyFromX(recipient.x);
    const ephemeral = generateKeyPairSync('x25519');
    const ephemeralX = rawX(ephemeral.publicKey);
    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientKey });
    const sealed = gcmEncrypt(kek(shared, ephemeralX, recipient.x, aad), contentKey, aad);
    return { kid: kidOf(recipient.x), epk: ephemeralX, iv: b64(sealed.iv), key: b64(sealed.ciphertext), tag: b64(sealed.tag) };
  });
  const body = gcmEncrypt(contentKey, pad(plaintext), aad);
  return Buffer.from(JSON.stringify({
    schema: HANDOFF_SCHEMA,
    recipients: wrapped,
    iv: b64(body.iv),
    ciphertext: b64(body.ciphertext),
    tag: b64(body.tag),
  }), 'utf8');
}

export function handoffDigest(envelope: Buffer): string {
  return createHash('sha256').update(envelope).digest('hex');
}

/**
 * Opens an envelope: digest first (pinned by the producer's job output), then
 * the recipient entry for this key, then AES-GCM under the consumer's OWN
 * expected AAD — a different run, attempt, target, job or artifact fails.
 */
export function openHandoff(
  envelope: Buffer,
  expectedDigest: string,
  privateKey: KeyObject,
  context: HandoffContext,
): Buffer {
  if (!/^[0-9a-f]{64}$/.test(expectedDigest)) throw new FailClosedError('expected handoff digest is malformed');
  if (handoffDigest(envelope) !== expectedDigest) throw new FailClosedError('handoff digest does not match the producer output');
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(envelope.toString('utf8')) as Record<string, unknown>; } catch { throw new FailClosedError('handoff envelope is malformed'); }
  if (parsed.schema !== HANDOFF_SCHEMA || !Array.isArray(parsed.recipients)) throw new FailClosedError('handoff envelope is malformed');
  const aad = aadOf(context);
  const myX = rawX(createPublicKey(privateKey));
  const entry = (parsed.recipients as Record<string, unknown>[]).find((candidate) => candidate.kid === kidOf(myX));
  if (entry === undefined) throw new FailClosedError('handoff is not addressed to this environment');
  if (typeof entry.epk !== 'string') throw new FailClosedError('handoff recipient entry is malformed');
  const shared = diffieHellman({ privateKey, publicKey: publicKeyFromX(entry.epk) });
  const contentKey = gcmDecrypt(kek(shared, entry.epk, myX, aad), unb64(entry.iv, 'iv'), unb64(entry.key, 'key'), unb64(entry.tag, 'tag'), aad);
  return unpad(gcmDecrypt(contentKey, unb64(parsed.iv, 'iv'), unb64(parsed.ciphertext, 'ciphertext'), unb64(parsed.tag, 'tag'), aad));
}
