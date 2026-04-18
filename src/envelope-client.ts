import {
  decryptV1,
  deserialize,
  downgradeToV1,
  encryptV1,
  serializeV1,
  serializeV2,
  upgradeToV2,
} from './envelope/index.js';
import { deriveCommitKey, deriveContentKey } from './primitives/hkdf.js';
import { SecureBuffer } from './secure-buffer.js';
import type { EnvelopeV1, ISecureBuffer } from './types.js';

export type WireFormat = 'v1' | 'v2';

export interface EnvelopeClientOptions {
  /**
   * 32-byte master key. Passed as a `Uint8Array` (copied into a
   * SecureBuffer internally and zeroed after derivation) or as a
   * pre-existing `ISecureBuffer` (not disposed by the client — the
   * caller owns its lifecycle).
   */
  masterKey: Uint8Array | ISecureBuffer;
  /** Wire format for `encrypt`. Defaults to `'v2'` (CBOR, ~33 % smaller). */
  format?: WireFormat;
  /** Opaque key identifier bound into the AAD. Defaults to `'default'`. */
  kid?: string;
}

/**
 * High-level envelope client. Holds HKDF-derived content and commit
 * keys in `SecureBuffer`s for the lifetime of the instance. Call
 * {@link EnvelopeClient.dispose} (or use `using`) when done.
 *
 *   using client = new EnvelopeClient({ masterKey });
 *   const wire = client.encrypt({ note: 'hello' });
 *   const back = client.decrypt(wire);
 */
export class EnvelopeClient {
  private readonly cek: ISecureBuffer;
  private readonly commitKey: ISecureBuffer;
  private readonly format: WireFormat;
  private readonly kid: string;
  private _disposed = false;

  constructor(options: EnvelopeClientOptions) {
    const masterBytes = getKeyBytes(options.masterKey);
    if (masterBytes.length !== 32) {
      throw new Error(`masterKey must be 32 bytes, got ${masterBytes.length}`);
    }

    const cekBytes = deriveContentKey(masterBytes);
    const commitBytes = deriveCommitKey(masterBytes);

    try {
      this.cek = SecureBuffer.from(cekBytes);
      this.commitKey = SecureBuffer.from(commitBytes);
    } finally {
      cekBytes.fill(0);
      commitBytes.fill(0);
    }

    this.format = options.format ?? 'v2';
    this.kid = options.kid ?? 'default';
  }

  /**
   * Encrypt a canonicalisable JSON payload. Returns wire bytes in the
   * configured format (v2 CBOR by default).
   */
  encrypt(payload: Record<string, unknown>): Uint8Array {
    this.assertLive();
    const v1 = encryptV1({
      payload,
      cek: new Uint8Array(this.cek.buffer),
      commitKey: new Uint8Array(this.commitKey.buffer),
      kid: this.kid,
    });
    return this.format === 'v2' ? serializeV2(upgradeToV2(v1)) : serializeV1(v1);
  }

  /**
   * Decrypt wire bytes. Auto-detects v1 JSON vs v2 CBOR on the magic
   * prefix. Returns the plaintext object. Throws on any cryptographic
   * mismatch (wrong key, tampered envelope, failed commitment).
   */
  decrypt(bytes: Uint8Array): Record<string, unknown> {
    this.assertLive();
    const env = deserialize(bytes);
    const v1: EnvelopeV1 = env.v === 1 ? env : downgradeToV1(env);
    return decryptV1(v1, new Uint8Array(this.cek.buffer), new Uint8Array(this.commitKey.buffer));
  }

  /** Zero the derived keys. Idempotent. */
  dispose(): void {
    if (this._disposed) {
      return;
    }
    this.cek.dispose();
    this.commitKey.dispose();
    this._disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  private assertLive(): void {
    if (this._disposed) {
      throw new Error('EnvelopeClient has been disposed');
    }
  }
}

function getKeyBytes(key: Uint8Array | ISecureBuffer): Uint8Array {
  if (key instanceof Uint8Array) {
    return key;
  }
  return new Uint8Array(key.buffer);
}
