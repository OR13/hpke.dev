/**
 * Layer-0 content encryption for COSE HPKE Key Encryption. HPKE wraps a random
 * CEK; the content itself is encrypted with a COSE AES-GCM content algorithm.
 * COSE carries the AEAD tag appended to the ciphertext (no separate tag field).
 */

/** COSE AES-GCM content-encryption algorithm identifiers (RFC 9053). */
export type CoseAeadAlg = 1 | 2 | 3; // A128GCM, A192GCM, A256GCM

export const AEAD_KEY_BYTES: Record<CoseAeadAlg, number> = { 1: 16, 2: 24, 3: 32 };
const IV_BYTES = 12;

export function isCoseAeadAlg(alg: unknown): alg is CoseAeadAlg {
  return alg === 1 || alg === 2 || alg === 3;
}

/** ArrayBuffer-backed view for Web Crypto's BufferSource (TS 5.7 strictness). */
function ab(u: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(u);
}

export function generateCek(alg: CoseAeadAlg): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(AEAD_KEY_BYTES[alg]));
}

export function generateIv(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(IV_BYTES));
}

async function importCek(alg: CoseAeadAlg, cek: Uint8Array): Promise<CryptoKey> {
  if (cek.length !== AEAD_KEY_BYTES[alg]) {
    throw new Error(`CEK is ${cek.length} bytes, expected ${AEAD_KEY_BYTES[alg]}`);
  }
  return crypto.subtle.importKey("raw", ab(cek), "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Returns ciphertext with the 16-byte GCM tag appended (COSE convention). */
export async function contentEncrypt(
  alg: CoseAeadAlg,
  cek: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const key = await importCek(alg, cek);
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ab(iv), additionalData: ab(aad), tagLength: 128 },
      key,
      ab(plaintext),
    ),
  );
}

export async function contentDecrypt(
  alg: CoseAeadAlg,
  cek: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const key = await importCek(alg, cek);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ab(iv), additionalData: ab(aad), tagLength: 128 },
      key,
      ab(ciphertext),
    ),
  );
}
