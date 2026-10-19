# @qmoosa/pqc-hybrid-tls-engine

Authenticated hybrid TLS 1.3 transport through maintained Node/OpenSSL, plus deprecated educational raw key-exchange helpers. Requires Node >=24.19.0 with X25519MLKEM768 support. Unsupported runtimes or peers fail closed.

## Authenticated transport

```ts
import { readFileSync } from 'node:fs';
import { connectAuthenticatedHybridTls, createAuthenticatedHybridTlsServer } from '@qmoosa/pqc-hybrid-tls-engine';

const server = createAuthenticatedHybridTlsServer({
  key: readFileSync('server-key.pem'), cert: readFileSync('server-chain.pem'),
}, socket => socket.on('data', data => socket.write(data)));
server.listen(8443, '127.0.0.1');

const socket = await connectAuthenticatedHybridTls({
  host: '127.0.0.1', port: 8443, servername: 'service.example',
  ca: readFileSync('trusted-ca.pem'), timeoutMs: 10000,
});
socket.on('error', error => console.error(error.message));
socket.write('hello');
// Close sockets/server when finished. Install normal application stream handlers.
```

Supply a certificate valid for the expected servername and a trusted CA; omitting ca uses the runtime trust store. The API requires TLS 1.3, X25519MLKEM768 and TLS_AES_256_GCM_SHA384. It validates the certificate, hostname and negotiated group/cipher before resolving. Extra caller properties cannot disable these checks. Node/OpenSSL performs the handshake, transcript, Finished verification, key schedule and record protection.

This provides server authentication; it does not implement mutual TLS. Hybrid key exchange does not make an RSA/ECDSA certificate post-quantum authenticated. No production security certification, deployment, QuickNode or x402 integration is claimed.

## Legacy helpers and compatibility

`HybridTlsEngine` is deprecated for transport. Its clientInit/serverRespond/clientComplete methods exchange raw ephemeral keys without identity authentication or Finished. They are educational helpers, not a complete interoperable TLS handshake. See [HANDSHAKE_AUDIT.md](docs/HANDSHAKE_AUDIT.md) for remaining wire-format/key-schedule/record gaps.

The reference HKDF-Expand-Label helper now uses Expand only, checked against published RFC 8448 key/IV vectors. This changes legacy derived outputs compared with the incorrect Extract+Expand behavior. It does not repair the entire legacy schedule. The raw record helper rejects sequence numbers outside unsigned 64-bit bounds; applications must never reuse a sequence/key pair.

## Build and verification

Build the sibling qmoosa-pqc-hybrid-tls-protocol repository first at commit f2e2a73688849190ee231bf887a2dbcc29324eda; the local dependency path is retained. Then run:

```sh
npm ci
npm test
npm run lint
```

Tests require an OpenSSL CLI to generate an ephemeral loopback-only test identity; set OPENSSL_BIN when it is not on PATH. No private identity is committed. Tests exercise actual sockets: trusted application data, exporter agreement, untrusted certificate, wrong hostname, classical-only peer, TLS 1.2 peer and stalled handshake. Published HKDF vectors and nonce boundary regressions are separate tests. These tests are development evidence, not an independent cryptographic audit.
