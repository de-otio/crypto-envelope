import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Per-key message counter. Exists to enforce AEAD per-key message budgets
 * — critically, AES-256-GCM's birthday bound (NIST SP 800-38D §8.3 caps
 * safe usage at 2³² encryptions per key with 96-bit random nonces).
 *
 * Keyring's rotation policy (`@de-otio/keyring` plan §7) watches the
 * counter to emit soft/hard threshold events before the envelope
 * client's own hard cap refuses further encryption.
 *
 * The interface is async to accommodate durable backends (SQLite,
 * DynamoDB, Redis) needed when a master key is used from more than one
 * process or host. The library ships an in-memory default suitable for
 * CLI/worker scenarios where a single process owns the key.
 */
export interface MessageCounter {
  /**
   * Atomically increment the counter for the given key fingerprint and
   * return the new value. Implementations must guarantee that two
   * concurrent `increment` calls never return the same value.
   */
  increment(keyFingerprint: Uint8Array): Promise<number>;

  /** Read the current counter without modifying it. */
  current(keyFingerprint: Uint8Array): Promise<number>;
}

/**
 * In-memory `MessageCounter` keyed by the hex of the fingerprint. Safe
 * for single-process use (CLI, short-lived server, Web Worker). Not
 * safe across process boundaries — every restart resets counters, so
 * consumers on AWS Lambda / serverless should supply a durable
 * implementation.
 *
 * Writes a one-time `console.warn` when first incremented so a caller
 * who accidentally uses the default in a multi-process topology is at
 * least made aware.
 */
export class InMemoryMessageCounter implements MessageCounter {
  private readonly _map = new Map<string, number>();
  private _warnEmitted = false;

  async increment(keyFingerprint: Uint8Array): Promise<number> {
    this.warnOnce();
    const key = toHex(keyFingerprint);
    const next = (this._map.get(key) ?? 0) + 1;
    this._map.set(key, next);
    return next;
  }

  async current(keyFingerprint: Uint8Array): Promise<number> {
    return this._map.get(toHex(keyFingerprint)) ?? 0;
  }

  /** Internal: reset for tests. */
  _reset(): void {
    this._map.clear();
    this._warnEmitted = false;
  }

  private warnOnce(): void {
    if (this._warnEmitted) return;
    this._warnEmitted = true;
    // eslint-disable-next-line no-console
    console.warn(
      '[@de-otio/crypto-envelope] InMemoryMessageCounter used — counters reset on every process ' +
        'restart, which can allow nonce-budget bypass under AES-GCM. Supply a durable MessageCounter ' +
        '(SQLite / DynamoDB / Redis) in multi-process or serverless topologies.',
    );
  }
}

/**
 * Compute a stable fingerprint for a master key. HMAC-SHA256 over the
 * commitment key with a fixed label, truncated to 16 bytes.
 *
 * The fingerprint is safe to persist and log — it reveals nothing about
 * the master (HMAC one-wayness) but is collision-resistant (128 bits of
 * output is more than enough for keyed-store indexing). Using the commit
 * key rather than the master or CEK keeps the fingerprint decoupled from
 * the keys that actually encrypt/MAC.
 */
export function keyFingerprint(commitKey: Uint8Array): Uint8Array {
  const full = hmac(sha256, commitKey, FINGERPRINT_LABEL);
  return full.subarray(0, 16);
}

const FINGERPRINT_LABEL = new TextEncoder().encode('crypto-envelope/v1/keyfp');

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return s;
}
