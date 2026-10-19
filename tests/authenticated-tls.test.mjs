import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { connectAuthenticatedHybridTls, createAuthenticatedHybridTlsServer } from '../dist/index.js';
let directory, key, cert;
before(async () => {
  directory = await fs.mkdtemp(path.join(os.tmpdir(), 'qmoosa-native-tls-'));
  const keyFile = path.join(directory, 'test-key.pem'); const certFile = path.join(directory, 'test-cert.pem');
  execFileSync(process.env.OPENSSL_BIN || 'openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'pipe', timeout: 20000 });
  key = await fs.readFile(keyFile); cert = await fs.readFile(certFile);
  console.log('Native runtime: ' + process.version + '; OpenSSL ' + process.versions.openssl);
});
after(async () => {
  if (directory) {
    const resolved = path.resolve(directory);
    if (path.dirname(resolved) !== path.resolve(os.tmpdir()) || !path.basename(resolved).startsWith('qmoosa-native-tls-')) throw new Error('Unexpected test cleanup directory');
    await fs.rm(resolved, { recursive: true, force: true });
  }
});
async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return server.address().port;
}
function options(port, extra = {}) { return { host: '127.0.0.1', port, servername: 'localhost', ca: cert, timeoutMs: 3000, ...extra }; }

test('real hybrid TLS authenticates the server and exchanges application data', async t => {
  const server = createAuthenticatedHybridTlsServer({ key, cert }, socket => socket.on('data', data => socket.write(data)));
  const port = await listen(t, server); const socket = await connectAuthenticatedHybridTls(options(port)); t.after(() => socket.destroy());
  assert.equal(socket.authorized, true); assert.equal(socket.getProtocol(), 'TLSv1.3');
  assert.equal(socket.getEphemeralKeyInfo().name, 'X25519MLKEM768');
  assert.equal(socket.getCipher().standardName, 'TLS_AES_256_GCM_SHA384');
  const response = new Promise((resolve, reject) => { socket.once('data', resolve); socket.once('error', reject); });
  socket.write('authenticated hybrid transport'); assert.equal((await response).toString(), 'authenticated hybrid transport');
});
test('client interoperates with a raw Node TLS server and agrees on an exporter', async t => {
  let exportFromServer;
  const server = tls.createServer({ key, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ecdhCurve: 'X25519MLKEM768', ciphers: 'TLS_AES_256_GCM_SHA384' }, socket => { exportFromServer = socket.exportKeyingMaterial(32, 'qmoosa-test-only-exporter'); socket.write('ready'); });
  const port = await listen(t, server); const socket = await connectAuthenticatedHybridTls(options(port)); t.after(() => socket.destroy());
  await new Promise((resolve, reject) => { socket.once('data', resolve); socket.once('error', reject); });
  assert.deepEqual(socket.exportKeyingMaterial(32, 'qmoosa-test-only-exporter'), exportFromServer);
});
test('untrusted server certificate is rejected even with an extra insecure option', async t => {
  const port = await listen(t, createAuthenticatedHybridTlsServer({ key, cert }));
  await assert.rejects(connectAuthenticatedHybridTls(options(port, { ca: undefined, rejectUnauthorized: false })), /self.signed|SELF_SIGNED|certificate/i);
});
test('wrong expected hostname is rejected', async t => {
  const port = await listen(t, createAuthenticatedHybridTlsServer({ key, cert }));
  await assert.rejects(connectAuthenticatedHybridTls(options(port, { servername: 'wrong.example' })), /Hostname|IP|altnames|ALTNAME/i);
});
test('classical-only peer cannot silently downgrade hybrid negotiation', async t => {
  const port = await listen(t, tls.createServer({ key, cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ecdhCurve: 'X25519' }));
  await assert.rejects(connectAuthenticatedHybridTls(options(port)), /handshake|alert|group|failure/i);
});
test('TLS 1.2-only peer cannot downgrade the protocol', async t => {
  const port = await listen(t, tls.createServer({ key, cert, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }));
  await assert.rejects(connectAuthenticatedHybridTls(options(port)), /protocol|version|alert|handshake/i);
});
test('stalled handshake has a bounded timeout', async t => {
  const port = await listen(t, net.createServer());
  await assert.rejects(connectAuthenticatedHybridTls(options(port, { timeoutMs: 100 })), /TLS_HANDSHAKE_TIMEOUT/);
});
test('missing identity and invalid client configuration fail closed', () => {
  assert.throws(() => createAuthenticatedHybridTlsServer({}), /MISSING_TLS_IDENTITY/);
  for (const extra of [{ servername: '' }, { port: 0 }, { timeoutMs: 0 }, { timeoutMs: Infinity }]) {
    assert.throws(() => connectAuthenticatedHybridTls(options(443, extra)), /INVALID_AUTHENTICATED_TLS_OPTIONS/);
  }
});
