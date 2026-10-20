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
    this.#codec = codec;
    this.#sendKey = Uint8Array.from(sendKey);
    this.#sendIV = Uint8Array.from(sendIV);
    this.#recvKey = Uint8Array.from(recvKey);
    this.#recvIV = Uint8Array.from(recvIV);
  }

  encrypt(plaintext: Uint8Array, contentType = 23): R {
    if (this.#closed) throw new Error('RECORD_SESSION_CLOSED');
    if (this.#nextSend >= LIMIT) throw new Error('RECORD_SEQUENCE_EXHAUSTED_REKEY_REQUIRED');
    if (!(plaintext instanceof Uint8Array) || plaintext.length > 16384) throw new Error('INVALID_RECORD_PLAINTEXT');
    const seq = this.#nextSend++;
    return this.#codec.encryptRecord(plaintext, this.#sendKey, this.#sendIV, seq, contentType);
  }

  decrypt(record: R): Uint8Array {
    if (this.#closed) throw new Error('RECORD_SESSION_CLOSED');
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
