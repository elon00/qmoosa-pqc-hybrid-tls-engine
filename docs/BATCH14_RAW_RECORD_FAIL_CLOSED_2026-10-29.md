# Batch 014 P1 — raw-record adapter fail-closed remediation (2026-10-29 UTC)

## Scope and status
This draft PR changes the deprecated `ReplayProtectedRecordSession` only. It does **not** make the custom record helper RFC 8446 TLS 1.3, multi-host safe, FIPS-validated, security-approved, or deployment-ready. Use authenticated, supported native TLS for any real network transport.

## Safety boundary
- By default construction throws `RAW_RECORD_ADAPTER_DISABLED`.
- The explicit `QMOOSA_ENABLE_UNSAFE_RAW_RECORD_TEST_ONLY=1` opt-in is **only** for isolated tests and is not an authorization for production.
- Tests must also provide an absolute `QMOOSA_RAW_RECORD_NONCE_REGISTRY_DIR`; otherwise construction fails closed.
- On a cooperating POSIX local filesystem, exclusive-create `wx` reservations, file fsync and directory fsync prevent the same outbound key/IV fingerprint from being reserved by a second process or after a restart. Only a SHA-256 fingerprint is stored, not key bytes. Reservations are never removed during the test.
- A non-atomic remote filesystem, separate hosts, state loss, compromised environment, directory permissions, unsupported fsync, and independent uncoordinated senders remain outside this local-only guarantee. No multi-host nonce uniqueness or production safety is claimed.
- This adapter's opt-in is not a security boundary against a process owner who intentionally modifies the environment or code.

## Required evidence
Run in a clean checkout alongside the pinned sibling protocol:
```sh
npm ci
npm run build
npm test
npm run lint
```
Do not accept a green check from an older SHA. Require restart and concurrent-process adversarial tests to pass on the exact current PR HEAD. Review other raw `HybridTlsEngine.encryptRecord` callers and authenticated TLS 1.3 transcript/peer identity/key schedule separately.

## Open gates
P1 remains open until production paths are independently confirmed to reject the deprecated raw adapter, all supported environments are checked, independent security review is complete, and all other Batch 14 acceptance tests pass. No deployment, FIPS claim, or production certification.
