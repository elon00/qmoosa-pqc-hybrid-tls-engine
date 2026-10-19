import test from 'node:test';
import assert from 'node:assert/strict';
import {
  HybridTlsEngine,
  computeRecordNonce,
  ReferenceTlsKeySchedule
} from '../dist/index.js';
import {
  X25519_MLKEM_768,
  constantTimeEqual
} from '@qmoosa/pqc-hybrid-tls-protocol';

test('Hybrid TLS Engine: Legacy raw key-exchange symmetry (not authenticated TLS)', () => {
  const engine = new HybridTlsEngine();

  // 1. Client creates ephemeral key shares
  const { clientState, clientKeyShare } = engine.clientInit();
  assert.equal(clientKeyShare.length, X25519_MLKEM_768.clientKeyShareBytes);

  // 2. Server processes ClientKeyShare and responds
  const transcript = new Uint8Array(32).fill(0x42);
  const { serverKeyShare, sessionKeys: serverKeys } = engine.serverRespond(clientKeyShare, transcript);
  assert.equal(serverKeyShare.length, X25519_MLKEM_768.serverKeyShareBytes);

  // 3. Client completes handshake
  const clientKeys = engine.clientComplete(clientState, serverKeyShare, transcript);

  // 4. Verify exact cryptographic symmetry
  assert.ok(
    constantTimeEqual(clientKeys.clientWriteKey, serverKeys.clientWriteKey),
    'Client write key must match server counterpart'
  );
  assert.ok(
    constantTimeEqual(clientKeys.serverWriteKey, serverKeys.serverWriteKey),
    'Server write key must match client counterpart'
  );
  assert.ok(
    constantTimeEqual(clientKeys.clientWriteIV, serverKeys.clientWriteIV),
    'Client write IV must match server counterpart'
  );
  assert.ok(
    constantTimeEqual(clientKeys.serverWriteIV, serverKeys.serverWriteIV),
    'Server write IV must match client counterpart'
  );
});

test('Hybrid TLS Engine: Legacy AEAD helper round trip (not TLS record interoperability)', () => {
  const engine = new HybridTlsEngine();
  const transcript = new Uint8Array(32).fill(0x99);

  const { clientState, clientKeyShare } = engine.clientInit();
  const { serverKeyShare, sessionKeys: serverKeys } = engine.serverRespond(clientKeyShare, transcript);
  const clientKeys = engine.clientComplete(clientState, serverKeyShare, transcript);

  // Message 1: Client -> Server
  const clientMsg = new TextEncoder().encode('POST /api/v1/quantum-settlement HTTP/1.1\r\nHost: qmoosa.network');
  const record1 = engine.encryptRecord(clientMsg, clientKeys.clientWriteKey, clientKeys.clientWriteIV, 0n);

  const decryptedByServer = engine.decryptRecord(record1, serverKeys.clientWriteKey, serverKeys.clientWriteIV);
  assert.deepEqual(decryptedByServer, clientMsg, 'Server must correctly decrypt client record');

  // Message 2: Server -> Client
  const serverMsg = new TextEncoder().encode('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"CONFIRMED"}');
  const record2 = engine.encryptRecord(serverMsg, serverKeys.serverWriteKey, serverKeys.serverWriteIV, 0n);

  const decryptedByClient = engine.decryptRecord(record2, clientKeys.serverWriteKey, clientKeys.serverWriteIV);
  assert.deepEqual(decryptedByClient, serverMsg, 'Client must correctly decrypt server response');
});

test('Hybrid TLS Engine: Adversarial Negative Control - Tampered Ciphertext Rejection', () => {
  const engine = new HybridTlsEngine();
  const { clientState, clientKeyShare } = engine.clientInit();
  const { serverKeyShare, sessionKeys } = engine.serverRespond(clientKeyShare);

  const msg = new TextEncoder().encode('Transfer 1000 QMOOSA');
  const record = engine.encryptRecord(msg, sessionKeys.clientWriteKey, sessionKeys.clientWriteIV, 1n);

  // Attacker flips bit in ciphertext
  const forgedCiphertext = new Uint8Array(record.ciphertext);
  forgedCiphertext[5] ^= 0x01;

  const forgedRecord = {
    ...record,
    ciphertext: forgedCiphertext
  };

  assert.throws(
    () => engine.decryptRecord(forgedRecord, sessionKeys.clientWriteKey, sessionKeys.clientWriteIV),
    /TLS_RECORD_AUTHENTICATION_FAILURE/
  );
});

test('Hybrid TLS Engine: Adversarial Negative Control - Out-of-Order Sequence Rejection', () => {
  const engine = new HybridTlsEngine();
  const { clientState, clientKeyShare } = engine.clientInit();
  const { serverKeyShare, sessionKeys } = engine.serverRespond(clientKeyShare);

  const msg = new TextEncoder().encode('Secure State Update');
  // Encrypted with sequence number 5
  const record = engine.encryptRecord(msg, sessionKeys.clientWriteKey, sessionKeys.clientWriteIV, 5n);

  // Verifier attempts to decrypt with sequence number 6 (replay / out-of-order)
  assert.throws(
    () => engine.decryptRecord(record, sessionKeys.clientWriteKey, sessionKeys.clientWriteIV, 6n),
    /TLS_RECORD_AUTHENTICATION_FAILURE/
  );
});

test('Hybrid TLS Engine: Adversarial Negative Control - Corrupted Server ML-KEM Ciphertext Rejection', () => {
  const engine = new HybridTlsEngine();
  const { clientState, clientKeyShare } = engine.clientInit();
  const { serverKeyShare } = engine.serverRespond(clientKeyShare);

  // Attacker tampers with ML-KEM ciphertext in ServerKeyShare
  const tamperedServerShare = new Uint8Array(serverKeyShare);
  tamperedServerShare[100] ^= 0xff;

  const clientKeys = engine.clientComplete(clientState, tamperedServerShare);

  // The client keys will NOT match because decapsulation of altered ciphertext produces a pseudo-random different key (implicit rejection)
  const { sessionKeys: serverKeys } = engine.serverRespond(clientKeyShare);
  assert.equal(
    constantTimeEqual(clientKeys.clientWriteKey, serverKeys.clientWriteKey),
    false,
    'Tampered ML-KEM ciphertext must produce non-matching keys'
  );
});

test('Hybrid TLS Engine: Reference Key Schedule Verification', () => {
  assert.ok(ReferenceTlsKeySchedule);
  const secret = new Uint8Array(32).fill(0x01);
  const label = 'key';
  const derived = ReferenceTlsKeySchedule.hkdfExpandLabel(secret, label, new Uint8Array(0), 32);
  assert.equal(derived.length, 32);

  const nonce = computeRecordNonce(new Uint8Array(12).fill(0xaa), 1n);
  assert.equal(nonce.length, 12);
});

// RFC 8446 section 5.3 sequence-number boundary regressions.
const hex = bytes => Buffer.from(bytes).toString('hex');

test('nonce bounds: zero retains the IV', () => {
  const iv = new Uint8Array(12).fill(0x55);
  assert.equal(hex(computeRecordNonce(iv, 0n)), '555555555555555555555555');
});
test('nonce bounds: one uses network-byte-order XOR', () => {
  assert.equal(hex(computeRecordNonce(new Uint8Array(12), 1n)), '000000000000000000000001');
});
test('nonce bounds: maximum uint64 is accepted', () => {
  assert.equal(hex(computeRecordNonce(new Uint8Array(12), (1n << 64n) - 1n)), '00000000ffffffffffffffff');
});
test('nonce bounds: negative values are rejected', () => {
  assert.throws(() => computeRecordNonce(new Uint8Array(12), -1n), /INVALID_SEQUENCE_NUMBER/);
});
test('nonce bounds: uint64 overflow is rejected before truncation', () => {
  assert.throws(() => computeRecordNonce(new Uint8Array(12), 1n << 64n), /INVALID_SEQUENCE_NUMBER/);
});
test('nonce bounds: larger overflow is rejected', () => {
  assert.throws(() => computeRecordNonce(new Uint8Array(12), 1n << 80n), /INVALID_SEQUENCE_NUMBER/);
});
test('nonce bounds: runtime non-bigint inputs are rejected', () => {
  for (const value of [0, 1, '1', null, undefined]) {
    assert.throws(() => computeRecordNonce(new Uint8Array(12), value), /INVALID_SEQUENCE_NUMBER/);
  }
});
test('nonce bounds: invalid IV length remains rejected', () => {
  assert.throws(() => computeRecordNonce(new Uint8Array(11), 0n), /INVALID_IV_LENGTH/);
});

test('record API: encryption rejects invalid sequence numbers', () => {
  const engine = new HybridTlsEngine();
  const key = new Uint8Array(32).fill(0x11);
  const iv = new Uint8Array(12).fill(0x22);
  for (const sequence of [-1n, 1n << 64n, 1n << 80n]) {
    assert.throws(
      () => engine.encryptRecord(new Uint8Array([1, 2, 3]), key, iv, sequence),
      /INVALID_SEQUENCE_NUMBER/
    );
  }
});

test('record API: decryption rejects overflowing explicit and stored sequences', () => {
  const engine = new HybridTlsEngine();
  const key = new Uint8Array(32).fill(0x11);
  const iv = new Uint8Array(12).fill(0x22);
  const record = engine.encryptRecord(new Uint8Array([1, 2, 3]), key, iv, 0n);
  assert.throws(() => engine.decryptRecord(record, key, iv, 1n << 64n), /INVALID_SEQUENCE_NUMBER/);
  assert.throws(
    () => engine.decryptRecord({ ...record, sequenceNumber: 1n << 64n }, key, iv),
    /INVALID_SEQUENCE_NUMBER/
  );
  assert.throws(
    () => engine.decryptRecord({ ...record, sequenceNumber: -1n }, key, iv),
    /INVALID_SEQUENCE_NUMBER/
  );
});

test('record API: maximum uint64 sequence encrypts and decrypts correctly', () => {
  const engine = new HybridTlsEngine();
  const key = new Uint8Array(32).fill(0x11);
  const iv = new Uint8Array(12).fill(0x22);
  const message = new Uint8Array([1, 2, 3]);
  const record = engine.encryptRecord(message, key, iv, (1n << 64n) - 1n);
  assert.deepEqual(engine.decryptRecord(record, key, iv), message);
});
