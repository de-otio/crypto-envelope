/**
 * Compiles and runs the code examples from README.md so that any drift
 * between the README and the public API is caught in CI. If you change
 * the README, change this file in lockstep.
 */
import { describe, expect, it } from 'vitest';
import {
  EnvelopeClient,
  decryptV1,
  deriveCommitKey,
  deriveContentKey,
  deriveMasterKeyFromPassphrase,
  encryptV1,
} from '../src/index.js';

describe('README quick-start examples', () => {
  it('high-level EnvelopeClient round-trip (README §Quick start)', async () => {
    using client = new EnvelopeClient({
      masterKey: crypto.getRandomValues(new Uint8Array(32)),
    });

    const wire = await client.encrypt({ type: 'note', body: 'hello' });
    const back = await client.decrypt(wire);

    expect(back).toEqual({ type: 'note', body: 'hello' });
  });

  it('passphrase unlock with Argon2id (README §Passphrase unlock)', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const masterKey = await deriveMasterKeyFromPassphrase(
      'correct horse battery staple',
      salt,
      { algorithm: 'argon2id' },
    );

    using client = new EnvelopeClient({ masterKey });
    const wire = await client.encrypt({ ok: true });
    expect(await client.decrypt(wire)).toEqual({ ok: true });
  });

  it('AES-GCM interop client (README §AES-256-GCM for interop)', async () => {
    const masterKey = crypto.getRandomValues(new Uint8Array(32));
    using client = EnvelopeClient.forAesGcmInterop({ masterKey });
    const wire = await client.encrypt({ payload: 1 });
    expect(await client.decrypt(wire)).toEqual({ payload: 1 });
  });

  it('low-level deriveContentKey / deriveCommitKey from main entry (README §finer control)', () => {
    const masterKey = crypto.getRandomValues(new Uint8Array(32));
    const cek = deriveContentKey(masterKey);
    const commitKey = deriveCommitKey(masterKey);
    const envelope = encryptV1({ payload: { x: 1 }, cek, commitKey, kid: 'default' });
    const recovered = decryptV1(envelope, cek, commitKey);
    expect(recovered).toEqual({ x: 1 });
  });
});
