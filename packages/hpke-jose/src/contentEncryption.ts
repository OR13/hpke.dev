/**
 * JWE content encryption for HPKE Key Encryption mode.
 *
 * In Key Encryption, HPKE only wraps a randomly-generated Content Encryption
 * Key (CEK); the plaintext itself is encrypted with a standard JWE `enc`
 * content-encryption algorithm using that CEK. We implement the AES-GCM family
 * (A128GCM/A192GCM/A256GCM) via Web Crypto.
 */

export type JweEnc = "A128GCM" | "A192GCM" | "A256GCM";

export const ENC_KEY_BYTES: Record<JweEnc, number> = {
  A128GCM: 16,
  A192GCM: 24,
  A256GCM: 32,
};

const IV_BYTES = 12;
const TAG_BYTES = 16;

export function isJweEnc(enc: unknown): enc is JweEnc {
  return typeof enc === "string" && enc in ENC_KEY_BYTES;
}

/** Generate a fresh random CEK sized for the given content-encryption algorithm. */
export function generateCek(enc: JweEnc): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(ENC_KEY_BYTES[enc]));
}

async function importCek(enc: JweEnc, cek: Uint8Array): Promise<CryptoKey> {
  if (cek.length !== ENC_KEY_BYTES[enc]) {
    throw new Error(`CEK is ${cek.length} bytes, expected ${ENC_KEY_BYTES[enc]} for ${enc}`);
  }
  return crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/**
 * AEAD-encrypt plaintext under the CEK, returning the JWE iv/ciphertext/tag.
 * Web Crypto appends the 16-byte GCM tag to the ciphertext; JWE carries them
 * separately, so we split the trailing tag off.
 */
export async function contentEncrypt(
  enc: JweEnc,
  cek: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await importCek(enc, cek);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: TAG_BYTES * 8 },
      key,
      plaintext,
    ),
  );
  return {
    iv,
    ciphertext: sealed.slice(0, sealed.length - TAG_BYTES),
    tag: sealed.slice(sealed.length - TAG_BYTES),
  };
}

/** AEAD-decrypt JWE iv/ciphertext/tag under the CEK. */
export async function contentDecrypt(
  enc: JweEnc,
  cek: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const key = await importCek(enc, cek);
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext);
  sealed.set(tag, ciphertext.length);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: TAG_BYTES * 8 },
      key,
      sealed,
    ),
  );
}
