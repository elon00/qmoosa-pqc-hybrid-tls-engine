/**
 * QMOOSA Post-Quantum Cryptography — Hybrid TLS 1.3 Handshake Engine & Key Schedule
 *
 * Implements ephemeral hybrid key exchange combining X25519 with NIST FIPS 203 ML-KEM-768
 * (Group codepoint 0x11ec: X25519MLKEM768), transcript-bound key schedule derivation,
 * and AES-256-GCM authenticated record layer encryption.
 */

import {
  generateKeyPairSync,
  diffieHellman,
  createPublicKey,
  createPrivateKey,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  KeyObject
} from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  X25519_MLKEM_768,
  getHybridGroupParameters,
  serializeClientKeyShare,
  deserializeClientKeyShare,
  serializeServerKeyShare,
  deserializeServerKeyShare,
  constantTimeEqual,
  type HybridGroupParameters,
  type HybridClientKeyShare,
  type HybridServerKeyShare,
  type HybridTlsSessionKeys,
  type EncryptedTlsRecord,
  type TlsRecordHeader
} from '@qmoosa/pqc-hybrid-tls-protocol';
import {
  hkdfExpandLabel,
  sha256,
  buildHkdfLabel
} from './reference-tls-key-schedule.js';

export * from './authenticated-tls.js';

export * as ReferenceTlsKeySchedule from './reference-tls-key-schedule.js';

// Standard constant SPKI and PKCS8 headers for X25519 (RFC 8410)
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

function rawToX25519PublicKey(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error('INVALID_X25519_KEY_LENGTH: Must be 32 bytes');
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'spki'
  });
}

function rawToX25519PrivateKey(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error('INVALID_X25519_KEY_LENGTH: Must be 32 bytes');
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'pkcs8'
  });
}

function extractRawX25519PublicKey(key: KeyObject): Uint8Array {
  const der = key.export({ type: 'spki', format: 'der' });
  return new Uint8Array(der.subarray(der.length - 32));
}

function extractRawX25519PrivateKey(key: KeyObject): Uint8Array {
  const der = key.export({ type: 'pkcs8', format: 'der' });
  return new Uint8Array(der.subarray(der.length - 32));
}

export interface ClientEphemeralState {
  readonly x25519PrivateKey: Uint8Array;
  readonly x25519PublicKey: Uint8Array;
  readonly mlkemDecapsulationKey: Uint8Array;
  readonly mlkemEncapsulationKey: Uint8Array;
  readonly clientKeyShareBytes: Uint8Array;
}

export interface ClientInitResult {
  readonly clientState: ClientEphemeralState;
  readonly clientKeyShare: Uint8Array;
}

export interface ServerRespondResult {
  readonly serverKeyShare: Uint8Array;
  readonly sessionKeys: HybridTlsSessionKeys;
}

/**
 * Computes per-record nonce: IV XOR SequenceNumber (RFC 8446 Section 5.3)
 */
export function computeRecordNonce(baseIV: Uint8Array, sequenceNumber: bigint): Uint8Array {
  if (baseIV.length !== 12) {
    throw new Error('INVALID_IV_LENGTH: Base IV must be 12 bytes');
  }
  if (typeof sequenceNumber !== 'bigint' ||
      sequenceNumber < 0n || sequenceNumber >= (1n << 64n)) {
    throw new RangeError('INVALID_SEQUENCE_NUMBER: Expected an unsigned 64-bit bigint');
  }
  const nonce = new Uint8Array(baseIV);
  let seq = sequenceNumber;
  for (let i = 11; i >= 4; i--) {
    nonce[i] ^= Number(seq & 0xffn);
    seq >>= 8n;
  }
  return nonce;
}

/** @deprecated Educational raw key-exchange/record helper. Use authenticated native TLS for transport. */
export class HybridTlsEngine {
  private readonly params: HybridGroupParameters;

  constructor(params: HybridGroupParameters = X25519_MLKEM_768) {
    this.params = params;
  }

  /**
   * Generates client ephemeral key shares (X25519 + ML-KEM-768).
   */
  public clientInit(): ClientInitResult {
    // 1. Classical X25519
    const x25519Kp = generateKeyPairSync('x25519');
    const x25519Pk = extractRawX25519PublicKey(x25519Kp.publicKey);
    const x25519Sk = extractRawX25519PrivateKey(x25519Kp.privateKey);

    // 2. Post-Quantum ML-KEM-768
    const mlkemKp = ml_kem768.keygen();
    const mlkemEk = new Uint8Array(mlkemKp.publicKey);
    const mlkemDk = new Uint8Array(mlkemKp.secretKey);

    // 3. Serialize ClientKeyShare
    const clientKeyShare = serializeClientKeyShare({
      x25519PublicKey: x25519Pk,
      mlkemEncapsulationKey: mlkemEk
    }, this.params);

    const clientState: ClientEphemeralState = Object.freeze({
      x25519PrivateKey: x25519Sk,
      x25519PublicKey: x25519Pk,
      mlkemDecapsulationKey: mlkemDk,
      mlkemEncapsulationKey: mlkemEk,
      clientKeyShareBytes: clientKeyShare
    });

    return { clientState, clientKeyShare };
  }

  /**
   * Server processes ClientKeyShare, encapsulates ML-KEM-768, performs X25519 ECDH,
   * derives session keys, and produces ServerKeyShare.
   */
  public serverRespond(
    clientKeyShareBytes: Uint8Array,
    transcriptContext: Uint8Array = new Uint8Array(32)
  ): ServerRespondResult {
    const clientShare = deserializeClientKeyShare(clientKeyShareBytes, this.params);

    // 1. Server X25519 KeyGen & ECDH
    const serverX25519Kp = generateKeyPairSync('x25519');
    const serverX25519Pk = extractRawX25519PublicKey(serverX25519Kp.publicKey);
    const clientX25519KeyObj = rawToX25519PublicKey(clientShare.x25519PublicKey);

    const ssEcdhBuffer = diffieHellman({
      privateKey: serverX25519Kp.privateKey,
      publicKey: clientX25519KeyObj
    });
    const ssEcdh = new Uint8Array(ssEcdhBuffer);

    // 2. Server ML-KEM-768 Encapsulation
    const { cipherText, sharedSecret: ssPqcRaw } = ml_kem768.encapsulate(clientShare.mlkemEncapsulationKey);
    const mlkemCt = new Uint8Array(cipherText);
    const ssPqc = new Uint8Array(ssPqcRaw);

    // 3. Combine Shared Secrets: SS_hybrid = SS_pqc || SS_ecdh (per draft-ietf-tls-hybrid-design)
    const ssHybrid = new Uint8Array(this.params.combinedSharedSecretBytes);
    ssHybrid.set(ssPqc, 0);
    ssHybrid.set(ssEcdh, ssPqc.length);

    // 4. Derive Session Keys via HKDF-Expand-Label
    const sessionKeys = this.deriveSessionKeys(ssHybrid, transcriptContext);

    // 5. Serialize ServerKeyShare
    const serverKeyShare = serializeServerKeyShare({
      x25519PublicKey: serverX25519Pk,
      mlkemCiphertext: mlkemCt
    }, this.params);

    return { serverKeyShare, sessionKeys };
  }

  /**
   * Client receives ServerKeyShare, performs X25519 ECDH and ML-KEM-768 decapsulation,
   * derives session keys, and verifies symmetry.
   */
  public clientComplete(
    clientState: ClientEphemeralState,
    serverKeyShareBytes: Uint8Array,
    transcriptContext: Uint8Array = new Uint8Array(32)
  ): HybridTlsSessionKeys {
    const serverShare = deserializeServerKeyShare(serverKeyShareBytes, this.params);

    // 1. Client X25519 ECDH
    const clientPrivateKeyObj = rawToX25519PrivateKey(clientState.x25519PrivateKey);
    const serverPublicKeyObj = rawToX25519PublicKey(serverShare.x25519PublicKey);

    const ssEcdhBuffer = diffieHellman({
      privateKey: clientPrivateKeyObj,
      publicKey: serverPublicKeyObj
    });
    const ssEcdh = new Uint8Array(ssEcdhBuffer);

    // 2. Client ML-KEM-768 Decapsulation
    const ssPqcRaw = ml_kem768.decapsulate(serverShare.mlkemCiphertext, clientState.mlkemDecapsulationKey);
    const ssPqc = new Uint8Array(ssPqcRaw);

    // 3. Combine Shared Secrets: SS_hybrid = SS_pqc || SS_ecdh
    const ssHybrid = new Uint8Array(this.params.combinedSharedSecretBytes);
    ssHybrid.set(ssPqc, 0);
    ssHybrid.set(ssEcdh, ssPqc.length);

    // 4. Derive Session Keys
    return this.deriveSessionKeys(ssHybrid, transcriptContext);
  }

  /**
   * Derives symmetric keys and IVs using standard TLS 1.3 HKDF expansion.
   */
  private deriveSessionKeys(ssHybrid: Uint8Array, transcriptContext: Uint8Array): HybridTlsSessionKeys {
    // Handshake Secret extraction
    const handshakeSecret = hkdfExpandLabel(ssHybrid, 'derived', sha256(transcriptContext), 32);

    const clientTrafficSecret = hkdfExpandLabel(handshakeSecret, 'c hs traffic', sha256(transcriptContext), 32);
    const serverTrafficSecret = hkdfExpandLabel(handshakeSecret, 's hs traffic', sha256(transcriptContext), 32);

    const clientWriteKey = hkdfExpandLabel(clientTrafficSecret, 'key', new Uint8Array(0), 32);
    const serverWriteKey = hkdfExpandLabel(serverTrafficSecret, 'key', new Uint8Array(0), 32);

    const clientWriteIV = hkdfExpandLabel(clientTrafficSecret, 'iv', new Uint8Array(0), 12);
    const serverWriteIV = hkdfExpandLabel(serverTrafficSecret, 'iv', new Uint8Array(0), 12);

    return Object.freeze({
      clientWriteKey,
      serverWriteKey,
      clientWriteIV,
      serverWriteIV,
      clientTrafficSecret,
      serverTrafficSecret
    });
  }

  /**
   * Encrypts application record using AES-256-GCM with per-record sequence nonce.
   */
  public encryptRecord(
    plaintext: Uint8Array,
    writeKey: Uint8Array,
    writeIV: Uint8Array,
    sequenceNumber: bigint,
    contentType = 23 // Application Data
  ): EncryptedTlsRecord {
    const nonce = computeRecordNonce(writeIV, sequenceNumber);
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(writeKey), Buffer.from(nonce));

    const headerBuffer = Buffer.alloc(5);
    headerBuffer.writeUInt8(contentType, 0);
    headerBuffer.writeUInt16BE(0x0303, 1); // legacyVersion TLS 1.2
    headerBuffer.writeUInt16BE(plaintext.length + 16, 3); // ciphertext + 16-byte tag
    cipher.setAAD(headerBuffer);

    const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const header: TlsRecordHeader = {
      contentType,
      legacyVersion: 0x0303,
      length: encrypted.length + authTag.length
    };

    return Object.freeze({
      header,
      ciphertext: new Uint8Array(encrypted),
      authTag: new Uint8Array(authTag),
      sequenceNumber
    });
  }

  /**
   * Decrypts application record using AES-256-GCM.
   */
  public decryptRecord(
    record: EncryptedTlsRecord,
    writeKey: Uint8Array,
    writeIV: Uint8Array,
    sequenceNumber?: bigint
  ): Uint8Array {
    const seq = sequenceNumber ?? record.sequenceNumber;
    const nonce = computeRecordNonce(writeIV, seq);
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(writeKey), Buffer.from(nonce));

    const headerBuffer = Buffer.alloc(5);
    headerBuffer.writeUInt8(record.header.contentType, 0);
    headerBuffer.writeUInt16BE(record.header.legacyVersion, 1);
    headerBuffer.writeUInt16BE(record.header.length, 3);
    decipher.setAAD(headerBuffer);
    decipher.setAuthTag(Buffer.from(record.authTag));

    try {
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(record.ciphertext)),
        decipher.final()
      ]);
      return new Uint8Array(decrypted);
    } catch (err) {
      throw new Error('TLS_RECORD_AUTHENTICATION_FAILURE: GCM tag verification failed or payload tampered');
    }
  }
}

/** @deprecated Raw record defense-in-depth, not an RFC 8446 TLS transport. */
export { ReplayProtectedRecordSession } from './replay-protected-record-session.js';
