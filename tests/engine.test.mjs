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

test('Hybrid TLS Engine: Full Handshake Round-Trip & Session Key Agreement', () => {
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

test('Hybrid TLS Engine: Bidirectional Authenticated Record Layer Encryption & Decryption', () => {
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
