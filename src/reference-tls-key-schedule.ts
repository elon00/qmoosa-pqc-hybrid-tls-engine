/**
 * QMOOSA Post-Quantum Cryptography — Educational Mathematical Reference
 * RFC 8446 Section 7.1: TLS 1.3 Key Schedule & HKDF-Expand-Label
 *
 * Implements the standard TLS 1.3 label formatting:
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 *   HKDF-Expand(Secret, HkdfLabel, Length)
 * where HkdfLabel = Length (2 bytes) || "tls13 " + Label (1 byte len + string) || Context (1 byte len + context)
 */

import { createHash } from 'node:crypto';
import { expand } from '@noble/hashes/hkdf.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * Builds the TLS 1.3 HkdfLabel structure per RFC 8446 Section 7.1.
 */
export function buildHkdfLabel(label: string, context: Uint8Array, length: number): Uint8Array {
  if (typeof label !== 'string' || !(context instanceof Uint8Array) ||
      !Number.isInteger(length) || length < 0 || length > 65535) {
    throw new Error('INVALID_HKDF_LABEL: Invalid label, context or uint16 length');
  }
  const labelPrefix = 'tls13 ';
  const fullLabel = Buffer.from(labelPrefix + label, 'utf8');

  if (fullLabel.length > 255 || context.length > 255) {
    throw new Error('INVALID_HKDF_LABEL: Encoded label and context must fit uint8 lengths');
  }

  const buf = Buffer.alloc(2 + 1 + fullLabel.length + 1 + context.length);
  let offset = 0;

  // Length (uint16)
  buf.writeUInt16BE(length, offset);
  offset += 2;

  // Label length & bytes
  buf.writeUInt8(fullLabel.length, offset);
  offset += 1;
  fullLabel.copy(buf, offset);
  offset += fullLabel.length;

  // Context length & bytes
  buf.writeUInt8(context.length, offset);
  offset += 1;
  Buffer.from(context).copy(buf, offset);

  return new Uint8Array(buf);
}

/**
 * TLS 1.3 HKDF-Expand-Label.
 */
export function hkdfExpandLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array = new Uint8Array(0),
  length: number = 32
): Uint8Array {
  const hkdfLabel = buildHkdfLabel(label, context, length);
  // The secret is already a PRK: Extract must not be performed again.
  return expand(nobleSha256, secret, hkdfLabel, length);
}

/**
 * Derives a sub-secret using Derive-Secret(Secret, Label, Messages) =
 *   HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
 */
export function deriveSecret(secret: Uint8Array, label: string, transcriptHash: Uint8Array): Uint8Array {
  return hkdfExpandLabel(secret, label, transcriptHash, 32);
}
