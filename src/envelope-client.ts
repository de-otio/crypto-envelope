import {
  decryptV1,
  deserialize,
  downgradeToV1,
  encryptV1,
  serializeV1,
  serializeV2,
  upgradeToV2,
} from './envelope/index.js';
import { InMemoryMessageCounter, type MessageCounter, keyFingerprint } from './message-counter.js';
import { deriveCommitKey, deriveContentKey } from './primitives/hkdf.js';
import { SecureBuffer } from './secure-buffer.js';
import type { Algorithm, EnvelopeV1, ISecureBuffer, MasterKey } from './types.js';

export type WireFormat = 'v1' | 'v2';

/**
 * Per-key AES-256-GCM message budget. NIST SP 800-38D §8.3 caps safe
 * use of 96-bit random nonces at 2³² encryptions — the birthday
 * probability of nonce collision passes 2⁻³³ beyond this. The envelope
 * client refuses further encryption once this threshold is reached
 * (design-review blocker B2).
 *
 * XChaCha20-Poly1305 has a 192-bit nonce and no practical cap; the
 * counter is still incremented for rotation-policy observability but
 * no hard refusal applies.
 */
export const AES_GCM_HARD_CAP = 2 ** 32;

/**
 * Error thrown when the per-key AES-GCM message budget is exhausted.
 * The wrapped `fingerprint` identifies which master key is out of
 * budget; the consumer is expected to rotate and retry.
 */
export class NonceBudgetExceeded extends Error {
  readonly code = 'NONCE_BUDGET_EXCEEDED';
  readonly fingerprint: Uint8Array;
  readonly counter: number;
  readonly algorithm: Algorithm;

  constructor(fingerprint: Uint8Array, counter: number, algorithm: Algorithm) {
    super(
      `per-key nonce budget exhausted for ${algorithm}: counter=${counter}, cap=${AES_GCM_HARD_CAP}. Rotate the master key and re-encrypt pending payloads.`,
    );
    this.name = 'NonceBudgetExceeded';
    this.fingerprint = fingerprint;
    this.counter = counter;
    this.algorithm = algorithm;
  }
}

export interface EnvelopeClientOptions {
  /**
   * 32-byte master key. Passed as a `Uint8Array` (copied into a
   * `SecureBuffer` internally and zeroed after derivation), a
   * pre-existing `ISecureBuffer` (not disposed by the client — the
   * caller owns its lifecycle), or a branded `MasterKey` produced by
   * `deriveMasterKeyFromPassphrase`.
   */
  masterKey: MasterKey | Uint8Array | ISecureBuffer;

  /**
   * AEAD algorithm. Defaults to `'XChaCha20-Poly1305'` — the recommended
   * choice for every new envelope. Select `'AES-256-GCM'` only for
   * interop with external systems or FIPS-constrained environments; see
   * {@link EnvelopeClient.forAesGcmInterop} for a safer call-site.
   */
  algorithm?: Algorithm;

  /** Wire format for `encrypt`. Defaults to `'v2'` (CBOR, ~33 % smaller). */
  format?: WireFormat;

  /** Opaque key identifier bound into the AAD. Defaults to `'default'`. */
  kid?: string;

  /**
   * Per-key message counter. Required for AES-256-GCM (the client
   * enforces the 2³² hard cap against it). For XChaCha20-Poly1305 the
   * counter is optional — the 192-bit nonce has no practical cap — but
   * supplying it enables rotation-policy observability for keyring.
   *
   * Default: an in-process `InMemoryMessageCounter`. **Warning**: the
   * in-memory implementation resets on every process restart, which is
   * unsafe for multi-process or serverless topologies. Supply a durable
   * implementation (SQLite, DynamoDB, Redis) in those settings.
   */
  messageCounter?: MessageCounter;
}

/**
 * High-level envelope client. Holds HKDF-derived content and commit
 * keys in `SecureBuffer`s for the lifetime of the instance. Call
 * {@link EnvelopeClient.dispose} (or use `using`) when done.
 *
 * ```ts
 * using client = new EnvelopeClient({ masterKey });
 * const wire = await client.encrypt({ note: 'hello' });
 * const back = await client.decrypt(wire);
 * ```
 *
 * Phase IV: `encrypt` / `decrypt` are now `async` because the message
 * counter integration supplies a `Promise`-returning interface for
 * durable backends. This is a breaking change within the pre-1.0 alpha
 * line; chaoskb's consumer updates in plan-01 Phase F.
 */
export class EnvelopeClient {
  private readonly cek: ISecureBuffer;
  private readonly commitKey: ISecureBuffer;
  private readonly algorithm: Algorithm;
  private readonly format: WireFormat;
  private readonly kid: string;
  private readonly messageCounter: MessageCounter;
  private readonly fingerprint: Uint8Array;
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

    this.algorithm = options.algorithm ?? 'XChaCha20-Poly1305';
    this.format = options.format ?? 'v2';
    this.kid = options.kid ?? 'default';
    this.messageCounter = options.messageCounter ?? new InMemoryMessageCounter();
    this.fingerprint = keyFingerprint(new Uint8Array(this.commitKey.buffer));
  }

  /**
   * Safer call-site for the AES-256-GCM path. The name is the
   * discoverable warning — consumers opting in here are on notice that
   * AES-GCM carries a per-key message cap that XChaCha20-Poly1305 does
   * not. Design-review blocker B9.
   *
   * Equivalent to `new EnvelopeClient({ ...options, algorithm: 'AES-256-GCM' })`.
   */
  static forAesGcmInterop(options: Omit<EnvelopeClientOptions, 'algorithm'>): EnvelopeClient {
    return new EnvelopeClient({ ...options, algorithm: 'AES-256-GCM' });
  }

  /** Expose the key fingerprint for consumers that wire rotation
   *  policies (keyring's `@de-otio/keyring`). 16 bytes, stable across
   *  process restarts, safe to persist and log. */
  get keyFingerprint(): Uint8Array {
    // Defensive copy — callers should not mutate the internal fingerprint.
    return new Uint8Array(this.fingerprint);
  }

  /** Current message-counter value for this master. Useful for
   *  rotation-policy triggers. */
  async currentCount(): Promise<number> {
    this.assertLive();
    return this.messageCounter.current(this.fingerprint);
  }

  /**
   * Encrypt a canonicalisable JSON payload. Returns wire bytes in the
   * configured format (v2 CBOR by default).
   *
   * Increments the per-key message counter. Throws
   * {@link NonceBudgetExceeded} if the counter crosses the AES-GCM hard
   * cap (2³²). The hard cap applies only to AES-256-GCM; XChaCha20-Poly1305
   * has no practical cap, and its counter is incremented for observability
   * only.
   */
  async encrypt(payload: Record<string, unknown>): Promise<Uint8Array> {
    this.assertLive();

    const next = await this.messageCounter.increment(this.fingerprint);
    if (this.algorithm === 'AES-256-GCM' && next > AES_GCM_HARD_CAP) {
      throw new NonceBudgetExceeded(this.fingerprint, next, this.algorithm);
    }

    const v1 = encryptV1({
      payload,
      cek: new Uint8Array(this.cek.buffer),
      commitKey: new Uint8Array(this.commitKey.buffer),
      kid: this.kid,
      algorithm: this.algorithm,
    });
    return this.format === 'v2' ? serializeV2(upgradeToV2(v1)) : serializeV1(v1);
  }

  /**
   * Decrypt wire bytes. Auto-detects v1 JSON vs v2 CBOR on the magic
   * prefix. Returns the plaintext object. Throws on any cryptographic
   * mismatch (wrong key, tampered envelope, failed commitment). Works
   * regardless of the algorithm used at encrypt time — the envelope
   * carries `enc.alg`.
   */
  async decrypt(bytes: Uint8Array): Promise<Record<string, unknown>> {
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

function getKeyBytes(key: MasterKey | Uint8Array | ISecureBuffer): Uint8Array {
  if (key instanceof Uint8Array) {
    return key;
  }
  return new Uint8Array(key.buffer);
}
