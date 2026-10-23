# Replay-protected legacy record adapter — security review checkpoint

Date: 2026-10-23. Scope: QMOOSA-1000 Batch 014, engine component.

## Threat model and limits
The `ReplayProtectedRecordSession` wraps the existing **deprecated educational** `HybridTlsEngine` AES-256-GCM record helper. It is NOT RFC 8446 TLS 1.3, is not wire interoperable, does not authenticate peer identity, does not implement a Finished message or certificate validation, and is not FIPS validated.

For authenticated application transport use `connectAuthenticatedHybridTls` / `createAuthenticatedHybridTlsServer` backed by Node/OpenSSL. These still require correct certificate trust and runtime capabilities.

## Current adapter properties to verify
- The sender chooses a monotonic uint64 sequence and refuses overflow.
- The receiver requires the exact next sequence, and only advances after authenticated decryption.
- GCM ciphertext/tag tampering fails authentication.
- Separate directional key/IV material is required; identical key AND IV is rejected.
- `close()` zeroes internal key/IV copies and prevents future use.
- The adapter assumes **unique session keys/IVs** and does not persist sequence state across process restarts. It cannot prevent key/nonce reuse across independently created sessions with the same keys. Do not reuse traffic keys or serialize the session as a persistent transport.

## Review gates before merge
1. The integration tests in `tests/replay-session.test.mjs` must run against the real `HybridTlsEngine` and actual handshake-derived keys on the PR SHA, not mocked codecs.
2. Confirm the full CI job, type check, and regression tests succeed; investigate any failures.
3. Independently review nonce/sequence lifecycle, crash recovery, key re-use prevention and API exposure. The raw helper remains deprecated even if tests pass.
4. Do not mark SECURITY_APPROVED, DEPLOYMENT_READY, TLS 1.3 certified or FIPS validated on the basis of these tests.
