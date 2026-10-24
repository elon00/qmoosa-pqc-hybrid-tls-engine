# Batch 014 — security review: raw record nonce lifecycle (2026-10-24)

**Scope:** `elon00/qmoosa-pqc-hybrid-tls-engine`, draft PR #2, branch `audit/replay-integration-20261023-r29`. This is a review finding, **not** an independent security approval.

## Source-evidenced P1 blocker: key/nonce reuse across sessions

- `src/replay-protected-record-session.ts`: each new `ReplayProtectedRecordSession` initializes `#nextSend = 0n` and `#nextReceive = 0n`. The constructor checks only that *within one instance* its send and receive key+IV pairs are not identical; it does **not** reject reuse of a send key+IV in a second instance.
- `src/index.ts`: `computeRecordNonce(baseIV, sequenceNumber)` deterministically XORs the sequence into the IV; `encryptRecord` uses AES-256-GCM with that nonce. Recreating an instance with the same send key and IV resets sequence to zero and repeats the GCM key/nonce pair.
- There is no durable sequence journal, global key/IV uniqueness registry, or crash-recovery guarantee in the reviewed adapter. A passing in-session replay test cannot establish cross-session nonce safety.
- `close()` zeroes *internal copies* only; caller-owned key material and other copies remain the caller's responsibility.

**Risk:** Reuse of an AES-GCM key/nonce pair can undermine confidentiality and authentication. Treat this as a **P1 security blocker** for any use of the raw adapter in a real transport; upgrade to P0 if exposure to live traffic is established. This is not a claim that the authenticated native Node/OpenSSL TLS transport has the same defect.

## Required fail-closed acceptance before security approval

1. Prove, with **real-engine** tests, that independent instances and restart/recovery cannot reuse a traffic key+nonce pair; or remove/disable the raw adapter from deployable/public transport paths and document the unsupported use case.
2. Add adversarial tests for cross-instance same key+IV reuse, crash/restart state loss, both directions, sequence exhaustion, ciphertext/tag tampering, and record reordering. Tests must fail when the guarantee is absent; do not mark an expected vulnerability as a security PASS.
3. Verify traffic keys and IVs are derived uniquely per authenticated session, bound to the correct peer and transcript, with correct key lifecycle and zeroization. Do not invent custom TLS/FIPS certification.
4. Run the full suite on the **PR head SHA**, retain CI logs and independent review sign-off. The existing seven replay tests and previous successful CI run do **not** satisfy the above gates.

## Local reproduction and review

```bash
gh repo clone elon00/qmoosa-pqc-hybrid-tls-engine
cd qmoosa-pqc-hybrid-tls-engine
gh pr checkout 2
npm ci
npm test
npm run lint
```

Review `src/replay-protected-record-session.ts`, `src/index.ts`, `tests/replay-session.test.mjs`. Confirm the peer protocol dependency is present as configured; do not silently mock it.

**Gate decision (2026-10-24):** SECURITY_APPROVED = **NO**; DEPLOYMENT_READY = **NO**; FIPS validated = **NOT CLAIMED**. Keep PR #2 draft until the above checks have independently verifiable evidence. No public-chain deployment, paid resources, or secrets are needed.
