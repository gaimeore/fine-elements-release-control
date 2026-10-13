/** A refusal that must stop the job before any further network or mutation. */
export class FailClosedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FailClosedError';
  }
}

export function failClosed(message: string): never {
  throw new FailClosedError(message);
}
