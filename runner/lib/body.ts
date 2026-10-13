/** Reads an S3 SDK response body (any of its runtime shapes) into bytes. */
export async function bodyToBytes(body: unknown): Promise<Uint8Array> {
  if (body instanceof Uint8Array) return new Uint8Array(body);
  if (typeof body === 'object' && body !== null) {
    const withTransform = body as { transformToByteArray?: () => Promise<Uint8Array> };
    if (typeof withTransform.transformToByteArray === 'function') return new Uint8Array(await withTransform.transformToByteArray());
    const withArrayBuffer = body as { arrayBuffer?: () => Promise<ArrayBuffer> };
    if (typeof withArrayBuffer.arrayBuffer === 'function') return new Uint8Array(await withArrayBuffer.arrayBuffer());
    if (Symbol.asyncIterator in body) {
      const chunks: Buffer[] = [];
      for await (const chunk of body as AsyncIterable<Uint8Array | string>) {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : Buffer.from(chunk));
      }
      return new Uint8Array(Buffer.concat(chunks));
    }
  }
  throw new TypeError('unsupported object body');
}
