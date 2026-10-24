import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { HybridTlsEngine, ReplayProtectedRecordSession } from '../dist/index.js';

// Integration tests exercise the actual HybridTlsEngine AEAD codec and
// handshake-derived directional keys. This is a DEPRECATED raw record helper,
// NOT an RFC 8446 TLS 1.3 record implementation or a certified transport.
function connectedSessions() {
  const engine = new HybridTlsEngine();
  const { clientState, clientKeyShare } = engine.clientInit();
  const transcript = randomBytes(32);
  const { serverKeyShare, sessionKeys: serverKeys } = engine.serverRespond(clientKeyShare, transcript);
  const clientKeys = engine.clientComplete(clientState, serverKeyShare, transcript);
  const client = new ReplayProtectedRecordSession(
    engine, clientKeys.clientWriteKey, clientKeys.clientWriteIV,
    clientKeys.serverWriteKey, clientKeys.serverWriteIV
  );
  const server = new ReplayProtectedRecordSession(
    engine, serverKeys.serverWriteKey, serverKeys.serverWriteIV,
    serverKeys.clientWriteKey, serverKeys.clientWriteIV
  );
  return { client, server };
}
const payload = value => new TextEncoder().encode(value);

test('real engine: bidirectional records have independent sequence counters', () => {
  const { client, server } = connectedSessions();
  const outbound = client.encrypt(payload('request'));
  assert.equal(outbound.sequenceNumber, 0n);
  assert.deepEqual(server.decrypt(outbound), payload('request'));
  const inbound = server.encrypt(payload('response'));
  assert.equal(inbound.sequenceNumber, 0n);
  assert.deepEqual(client.decrypt(inbound), payload('response'));
  assert.equal(client.encrypt(payload('next')).sequenceNumber, 1n);
  client.close(); server.close();
});

test('real engine: replay of an authenticated record is rejected', () => {
  const { client, server } = connectedSessions();
  const record = client.encrypt(payload('pay once'));
  assert.deepEqual(server.decrypt(record), payload('pay once'));
  assert.throws(() => server.decrypt(record), /REPLAY_OR_OUT_OF_ORDER_RECORD/);
  client.close(); server.close();
});

test('real engine: out-of-order delivery fails closed without advancing receive counter', () => {
  const { client, server } = connectedSessions();
  const first = client.encrypt(payload('first'));
  const second = client.encrypt(payload('second'));
  assert.throws(() => server.decrypt(second), /REPLAY_OR_OUT_OF_ORDER_RECORD/);
  assert.deepEqual(server.decrypt(first), payload('first'));
  assert.deepEqual(server.decrypt(second), payload('second'));
  client.close(); server.close();
});

test('real engine: AEAD tampering fails without consuming a valid sequence', () => {
  const { client, server } = connectedSessions();
  const original = client.encrypt(payload('authenticated'));
  const ciphertext = Uint8Array.from(original.ciphertext);
  ciphertext[0] ^= 0x80;
  assert.throws(() => server.decrypt({ ...original, ciphertext }), /TLS_RECORD_AUTHENTICATION_FAILURE/);
  assert.deepEqual(server.decrypt(original), payload('authenticated'));
  client.close(); server.close();
});

test('real engine: forged record sequence cannot bypass receiver sequence state', () => {
  const { client, server } = connectedSessions();
  const record = client.encrypt(payload('sequence zero'));
  assert.throws(() => server.decrypt({ ...record, sequenceNumber: 1n }), /REPLAY_OR_OUT_OF_ORDER_RECORD/);
  assert.deepEqual(server.decrypt(record), payload('sequence zero'));
  client.close(); server.close();
});

test('raw record session rejects invalid and direction-reused key material', () => {
  const engine = new HybridTlsEngine();
  const key = new Uint8Array(32).fill(0x11);
  const iv = new Uint8Array(12).fill(0x22);
  assert.throws(() => new ReplayProtectedRecordSession(engine, key, iv, key, iv), /DIRECTIONAL_KEY_IV_REUSE/);
  assert.throws(() => new ReplayProtectedRecordSession(engine, new Uint8Array(31), iv, key, iv), /INVALID_RECORD_SESSION_PARAMETERS/);
});

test('closed sessions reject all subsequent record operations', () => {
  const { client, server } = connectedSessions();
  const record = client.encrypt(payload('before close'));
  client.close();
  assert.throws(() => client.encrypt(payload('after close')), /RECORD_SESSION_CLOSED/);
  assert.throws(() => client.decrypt(record), /RECORD_SESSION_CLOSED/);
  assert.deepEqual(server.decrypt(record), payload('before close'));
  server.close();
});


/*
 * P1 SECURITY REGRESSION GATES — intentionally fail until the exported raw
 * adapter rejects traffic key/IV reuse across independent instances.
 * These in-process tests do NOT prove crash/restart persistence or FIPS/TLS
 * certification. Never weaken/skip them to obtain a green workflow.
 */
test('P1 nonce lifecycle: reject simultaneous sessions reusing an outbound key and IV', () => {
  const engine = new HybridTlsEngine();
  const sendKey = randomBytes(32);
  const sendIV = randomBytes(12);
  const first = new ReplayProtectedRecordSession(
    engine, sendKey, sendIV, randomBytes(32), randomBytes(12)
  );
  try {
    assert.throws(
      () => new ReplayProtectedRecordSession(
        engine, sendKey, sendIV, randomBytes(32), randomBytes(12)
      ),
      /TRAFFIC_KEY_IV_REUSE/
    );
  } finally {
    first.close();
  }
});

test('P1 nonce lifecycle: closing a session cannot reset key/IV uniqueness', () => {
  const engine = new HybridTlsEngine();
  const sendKey = randomBytes(32);
  const sendIV = randomBytes(12);
  const first = new ReplayProtectedRecordSession(
    engine, sendKey, sendIV, randomBytes(32), randomBytes(12)
  );
  first.encrypt(payload('first record before close'));
  first.close();
  assert.throws(
    () => new ReplayProtectedRecordSession(
      engine, sendKey, sendIV, randomBytes(32), randomBytes(12)
    ),
    /TRAFFIC_KEY_IV_REUSE/
  );
});
