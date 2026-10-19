# Hybrid TLS source audit, 19 October 2026

Scope: engine main 093edcb6fa9d31e7aacaa75901a802686ab52ccc and nonce-fix development parent 230f595b3efc5f925d6ccff64f3dc45761a1be4f; protocol f2e2a73688849190ee231bf887a2dbcc29324eda. This is an implementation audit by the development agent, not independent approval.

## Findings and treatment

1. Legacy raw KEX has no certificate identity validation or Finished. Added a separate native Node/OpenSSL TLS transport with mandatory server certificate/hostname validation, exact TLS 1.3/hybrid group/cipher, bounded handshake and no insecure option passthrough. Kept and deprecated the old interface so existing purposes are preserved.
2. Reference hkdfExpandLabel incorrectly called hkdfSync, which extracts and expands an already extracted secret. The published RFC 8448 server application key vector failed on the parent helper. Replaced it with maintained @noble/hashes 2.4.0 Expand-only, added key/IV golden vectors, label encoding and boundary tests. No custom cryptographic primitive was introduced.
3. Protocol encode/decode puts X25519 bytes before ML-KEM. Current group-specific draft requires ML-KEM then X25519 in client and server key shares. Existing protocol remains a legacy private format and is not used by the new native transport. Do not claim draft-compatible wire serialization for the legacy API.
4. Legacy deriveSessionKeys is not the RFC 8446 early/derived/extract/handshake/application schedule; optional zero/default context does not establish an actual handshake transcript. Legacy raw record routines do not supply TLSInnerPlaintext framing or a complete TLS record state machine. The helper-level HKDF correction does not resolve these findings.
5. Earlier nonce bounds fix rejects negative, non-bigint and overflowing sequences; maximum uint64 is covered. This does not enforce automatic sequence management or key updates in the educational raw API.

## Acceptance evidence and limits

The native transport uses maintained cryptography and actual loopback sockets. Positive application exchange and exporter equality are accompanied by rejection tests for untrusted identity, wrong hostname, classical-only peer, protocol downgrade, missing identity, invalid options and stalled handshake. The peer interoperability test uses the raw Node TLS API; it is not a separate-vendor interoperability audit. Ephemeral RSA test certificates establish test trust only. Server authentication remains classical; mutual TLS and post-quantum certificate signatures are not claimed.

Remaining product acceptance includes consumer SDK/dashboard integration, dedicated cross-repository/independent-stack tests, a migration strategy for legacy serialization, CodeQL, independent review, operational controls and approved release. All five repository roles and production gates remain incomplete. No money, chain deployment, hosted service or security certification is involved.

## Primary references

- [RFC 8446 section 7.1: TLS 1.3 key schedule](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1)
- [RFC 8448 section 3: published TLS 1.3 key and IV vectors](https://www.rfc-editor.org/rfc/rfc8448.html#section-3)
- [IETF ECDHE-MLKEM group-specific draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem): client ML-KEM public key then X25519 public key; server ML-KEM ciphertext then X25519 public key; shared secret ML-KEM then ECDH.
- [Node TLS API](https://nodejs.org/api/tls.html): certificate validation, supported groups, protocol/cipher selection and ephemeral group reporting. Executed runtime: Node 24.19.0 / OpenSSL 3.5.7.
