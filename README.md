# @qmoosa/pqc-hybrid-tls-engine

[![CI Gate](https://github.com/elon00/qmoosa-pqc-hybrid-tls-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/elon00/qmoosa-pqc-hybrid-tls-engine/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> QMOOSA Post-Quantum Cryptography Suite — Hybrid X25519 + ML-KEM-768 TLS 1.3 Handshake Engine & Key Schedule.

## Overview

`@qmoosa/pqc-hybrid-tls-engine` implements the core cryptographic handshake state machine and record layer encryption for quantum-safe TLS 1.3 transport.
It combines classical Curve25519 ECDH with NIST FIPS 203 ML-KEM-768 to derive combined shared secrets ($SS_{\text{hybrid}} = SS_{\text{pqc}} \parallel SS_{\text{ecdh}}$) and provides authenticated AES-256-GCM record protection.

## Features

- **Hybrid Ephemeral Key Exchange:** Generates X25519 and ML-KEM-768 key shares in single pass.
- **Transcript-Bound Key Schedule:** Derives handshake and application traffic keys using RFC 8446 HKDF-Expand-Label.
- **Authenticated Record Protection:** AES-256-GCM with per-record sequence nonces ($IV \oplus \text{seq\_num}$) and strict authentication tag verification.
- **Audited PQC Primitive:** Powered by `@noble/post-quantum/ml-kem.js`.

## Build & Test

```bash
npm install
npm run build
npm test
npm run lint
```

## Reality Gate Status

- Production Deployment Status: **LOCKED (0 / 1,000 certified)**
- Local Reality-Gate Verification: **ACTIVE**
