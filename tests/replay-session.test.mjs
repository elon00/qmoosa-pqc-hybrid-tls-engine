import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Unique local test-only registry; child processes inherit these settings.
const nonceRegistry = mkdtempSync(join(tmpdir(), 'qmoosa-nonce-regression-'));
process.env.QMOOSA_RAW_RECORD_NONCE_REGISTRY_DIR = nonceRegistry;
process.env.QMOOSA_ENABLE_UNSAFE_RAW_RECORD_TEST_ONLY = '1';
after(() => rmSync(nonceRegistry, { recursive: true, force: true }));
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


/*
 * P1 fail-closed regression: an in-memory registry cannot protect a restarted
 * process or another worker. This uses two real Node processes and the actual
 * compiled HybridTlsEngine codec. It intentionally FAILS until a durable,
 * multi-process-safe traffic-key/IV uniqueness mechanism is implemented.
 * No real credentials or persistent secret keys are used.
 */
test('P1 restart isolation: reject outbound key/IV reuse after a process exits', async () => {
  const { spawnSync } = await import('node:child_process');
  const sendKey = randomBytes(32);
  const sendIV = randomBytes(12);
  const childScript = `
    import { HybridTlsEngine, ReplayProtectedRecordSession } from './dist/index.js';
    const sendKey = Buffer.from(process.argv[1], 'hex');
    const sendIV = Buffer.from(process.argv[2], 'hex');
    try {
      const session = new ReplayProtectedRecordSession(
        new HybridTlsEngine(), sendKey, sendIV,
        Buffer.alloc(32, 0x73), Buffer.alloc(12, 0x27)
      );
      session.encrypt(new TextEncoder().encode('test-only record'));
      session.close();
      process.stdout.write('ACCEPTED');
    } catch (error) {
      process.stderr.write(String(error?.message ?? error));
      process.exitCode = 42;
    }
  `;
  const invoke = () => spawnSync(process.execPath, [
    '--input-type=module', '-e', childScript,
    sendKey.toString('hex'), sendIV.toString('hex')
  ], { encoding: 'utf8', timeout: 15000, cwd: process.cwd() });

  const first = invoke();
  assert.equal(first.status, 0, `initial sender must work: ${first.stderr}`);
  const afterRestart = invoke();
  assert.equal(
    afterRestart.status, 42,
    'P1: restarted/second process accepted the SAME outbound AES-GCM key/IV'
  );
  assert.match(afterRestart.stderr, /TRAFFIC_KEY_IV_REUSE/);
});


test('P1 fail-closed: raw adapter requires explicit test-only opt-in', () => {
  const saved = process.env.QMOOSA_ENABLE_UNSAFE_RAW_RECORD_TEST_ONLY;
  delete process.env.QMOOSA_ENABLE_UNSAFE_RAW_RECORD_TEST_ONLY;
  try {
    assert.throws(() => new ReplayProtectedRecordSession(
      new HybridTlsEngine(), randomBytes(32), randomBytes(12),
      randomBytes(32), randomBytes(12)
    ), /RAW_RECORD_ADAPTER_DISABLED/);
  } finally {
    if (saved === undefined) delete process.env.QMOOSA_ENABLE_UNSAFE_RAW_RECORD_TEST_ONLY;
    else process.env.QMOOSA_ENABLE_UNSAFE_RAW_RECORD_TEST_ONLY = saved;
  }
});

test('P1 fail-closed: missing local registry refuses raw record construction', () => {
  const saved = process.env.QMOOSA_RAW_RECORD_NONCE_REGISTRY_DIR;
  delete process.env.QMOOSA_RAW_RECORD_NONCE_REGISTRY_DIR;
  try {
    assert.throws(() => new ReplayProtectedRecordSession(
      new HybridTlsEngine(), randomBytes(32), randomBytes(12),
      randomBytes(32), randomBytes(12)
    ), /NONCE_REGISTRY_UNAVAILABLE/);
  } finally {
    if (saved === undefined) delete process.env.QMOOSA_RAW_RECORD_NONCE_REGISTRY_DIR;
    else process.env.QMOOSA_RAW_RECORD_NONCE_REGISTRY_DIR = saved;
  }
});

test('P1 concurrent processes: only one sender may reserve a repeated key/IV', async () => {
  const { spawn } = await import('node:child_process');
  const key = randomBytes(32).toString('hex');
  const iv = randomBytes(12).toString('hex');
  const script = `
    import { HybridTlsEngine, ReplayProtectedRecordSession } from './dist/index.js';
    try {
      const session = new ReplayProtectedRecordSession(
        new HybridTlsEngine(), Buffer.from(process.argv[1], 'hex'),
        Buffer.from(process.argv[2], 'hex'), Buffer.alloc(32, 0x73),
        Buffer.alloc(12, 0x27)
      );
      session.encrypt(new TextEncoder().encode('test-only concurrent record'));
      session.close();
    } catch (error) {
      process.stderr.write(String(error?.message ?? error));
      process.exitCode = 42;
    }
  `;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, key, iv], {
      cwd: process.cwd(), env: process.env
    });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', code => resolve({ code, stderr }));
  });
  const results = await Promise.all([run(), run()]);
  assert.deepEqual(results.map(x => x.code).sort((a, b) => a - b), [0, 42]);
  assert.match(results.find(x => x.code === 42).stderr, /TRAFFIC_KEY_IV_REUSE/);
});
