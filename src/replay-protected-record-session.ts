import { createHash } from 'node:crypto';
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, writeSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

/**
 * Defense-in-depth adapter for the DEPRECATED raw HybridTlsEngine record helper.
 * NOT an RFC 8446 record implementation; prefer authenticated Node/OpenSSL TLS.
 * Each session must receive fresh, unique traffic keys/IVs per direction.
 */
export interface RawRecord { readonly sequenceNumber: bigint; }
export interface RawRecordCodec<R extends RawRecord> {
  encryptRecord(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array, sequence: bigint, contentType?: number): R;
  decryptRecord(record: R, key: Uint8Array, iv: Uint8Array, sequence?: bigint): Uint8Array;
}
const LIMIT = 1n << 64n;

// Recheck on every record operation, not only at construction: a test-only
// session must fail closed if its opt-in/runtime is subsequently revoked.
// Environment variables remain defense in depth, NOT a production boundary.
function requireRawRecordTestMode(): void {
  if (process.env.NODE_ENV !== 'test' ||
      process.env.QMOOSA_ENABLE_UNSAFE_RAW_RECORD_TEST_ONLY !== '1') {
    throw new Error('RAW_RECORD_ADAPTER_DISABLED');
  }
}

// TEST-ONLY, same-host reservation. An exclusive-create file plus fsync
// rejects key/IV reuse across cooperating local processes and restarts.
// This is NOT a multi-host/remote-filesystem-safe nonce allocator, and the
// raw adapter must never be used as a production TLS transport.
function reserveOutboundKeyIv(fingerprint: string): void {
  const directory = process.env.QMOOSA_RAW_RECORD_NONCE_REGISTRY_DIR;
  if (!directory || !isAbsolute(directory)) throw new Error('NONCE_REGISTRY_UNAVAILABLE');
  try {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (!lstatSync(directory).isDirectory()) throw new Error('NONCE_REGISTRY_UNAVAILABLE');
  } catch {
    throw new Error('NONCE_REGISTRY_UNAVAILABLE');
  }
  let fd: number;
  try {
    fd = openSync(join(directory, fingerprint), 'wx', 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new Error('TRAFFIC_KEY_IV_REUSE');
    throw new Error('NONCE_REGISTRY_UNAVAILABLE');
  }
  try {
    writeSync(fd, 'reserved\\n');
    fsyncSync(fd);
  } catch {
    throw new Error('NONCE_REGISTRY_UNAVAILABLE');
  } finally {
    closeSync(fd);
  }
  // Do not allow a session to encrypt until the reservation is durable.
  try {
    const directoryFd = openSync(directory, 'r');
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } catch {
    throw new Error('NONCE_REGISTRY_UNAVAILABLE');
  }
}

export class ReplayProtectedRecordSession<R extends RawRecord> {
  readonly #codec: RawRecordCodec<R>;
  readonly #sendKey: Uint8Array;
  readonly #sendIV: Uint8Array;
  readonly #recvKey: Uint8Array;
  readonly #recvIV: Uint8Array;
  #nextSend = 0n;
  #nextReceive = 0n;
  #closed = false;

  constructor(codec: RawRecordCodec<R>, sendKey: Uint8Array, sendIV: Uint8Array,
              recvKey: Uint8Array, recvIV: Uint8Array) {
    if (!codec || typeof codec.encryptRecord !== 'function' || typeof codec.decryptRecord !== 'function' ||
        ![sendKey, sendIV, recvKey, recvIV].every(x => x instanceof Uint8Array) ||
        sendKey.length !== 32 || recvKey.length !== 32 || sendIV.length !== 12 || recvIV.length !== 12) {
      throw new Error('INVALID_RECORD_SESSION_PARAMETERS');
    }
    if (sendKey.every((x, i) => x === recvKey[i]) && sendIV.every((x, i) => x === recvIV[i])) {
      throw new Error('DIRECTIONAL_KEY_IV_REUSE');
    }
    // Only outbound key/IV pairs are reserved: the peer's receive pair must
    // match this sender's pair and must not be mistaken for a second sender.
    // Hashing avoids retaining raw key material in the process-wide registry.
    const fingerprint = createHash('sha256')
      .update('QMOOSA-RAW-RECORD-OUTBOUND-V1')
      .update(sendKey)
      .update(sendIV)
      .digest('hex');
    // Require BOTH an explicit test runtime and opt-in. This is only defense in depth:
    // environment variables are not a trusted production authorization boundary.
    requireRawRecordTestMode();
    reserveOutboundKeyIv(fingerprint);
    this.#codec = codec;
    this.#sendKey = Uint8Array.from(sendKey);
    this.#sendIV = Uint8Array.from(sendIV);
    this.#recvKey = Uint8Array.from(recvKey);
    this.#recvIV = Uint8Array.from(recvIV);
  }

  encrypt(plaintext: Uint8Array, contentType = 23): R {
    if (this.#closed) throw new Error('RECORD_SESSION_CLOSED');
    requireRawRecordTestMode();
    if (this.#nextSend >= LIMIT) throw new Error('RECORD_SEQUENCE_EXHAUSTED_REKEY_REQUIRED');
    if (!(plaintext instanceof Uint8Array) || plaintext.length > 16384) throw new Error('INVALID_RECORD_PLAINTEXT');
    const seq = this.#nextSend++;
    return this.#codec.encryptRecord(plaintext, this.#sendKey, this.#sendIV, seq, contentType);
  }

  decrypt(record: R): Uint8Array {
    if (this.#closed) throw new Error('RECORD_SESSION_CLOSED');
    requireRawRecordTestMode();
    if (this.#nextReceive >= LIMIT) throw new Error('RECORD_SEQUENCE_EXHAUSTED_REKEY_REQUIRED');
    if (!record || typeof record.sequenceNumber !== 'bigint' || record.sequenceNumber !== this.#nextReceive) {
      throw new Error('REPLAY_OR_OUT_OF_ORDER_RECORD');
    }
    const plaintext = this.#codec.decryptRecord(record, this.#recvKey, this.#recvIV, this.#nextReceive);
    this.#nextReceive++;
    return plaintext;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#sendKey.fill(0); this.#recvKey.fill(0); this.#sendIV.fill(0); this.#recvIV.fill(0);
  }
}
