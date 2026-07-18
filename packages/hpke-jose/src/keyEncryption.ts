import { base64url } from "jose";
import {
  cipherSuiteForAlg,
  isJoseHpkeAlg,
  DEFAULT_INTEGRATED_ALG_FOR_CRV,
  type KeyEncryptionAlg,
  type SuiteParams,
} from "./suites";
import { importPrivateKey, importPublicKey, type Jwk } from "./keys";
import {
  contentDecrypt,
  contentEncrypt,
  generateCek,
  isJweEnc,
  type JweEnc,
} from "./contentEncryption";

const encoder = new TextEncoder();

/**
 * JWE JSON Serialization for HPKE Key Encryption
 * (draft-ietf-jose-hpke-encrypt-22, Section 6).
 *
 * For Key Encryption:
 *  - the protected header carries `alg` (an HPKE-N-KE label), `enc` (a standard
 *    JWE content-encryption algorithm), and `ek` (the base64url HPKE
 *    encapsulated secret); it MAY carry `kid`
 *  - the JWE Encrypted Key is the HPKE Seal of a randomly-generated CEK
 *  - the CEK encrypts the plaintext with `enc`, yielding iv/ciphertext/tag
 */
export type HpkeKeyEncryptionJwe = {
  protected: string;
  encrypted_key: string;
  iv: string;
  ciphertext: string;
  tag: string;
  aad?: string;
};

export type KeyEncryptionEncryptOptions = {
  /** Override the HPKE Key Encryption algorithm. */
  alg?: KeyEncryptionAlg;
  /** Content-encryption algorithm; defaults per the chosen `-KE` algorithm. */
  enc?: JweEnc;
  /** Additional protected header parameters (e.g. `kid`). */
  protectedHeader?: Record<string, unknown>;
  /** Optional JWE AAD, integrity-protected but not encrypted. */
  aad?: Uint8Array;
};

const DEFAULT_ENC: Record<KeyEncryptionAlg, JweEnc> = {
  "HPKE-0-KE": "A128GCM",
  "HPKE-1-KE": "A256GCM",
  "HPKE-2-KE": "A256GCM",
  "HPKE-3-KE": "A128GCM",
  "HPKE-5-KE": "A256GCM",
  "HPKE-7-KE": "A256GCM",
};

/** Resolve the Key Encryption algorithm for a recipient JWK. */
export function resolveKeyEncryptionAlg(jwk: Jwk, override?: KeyEncryptionAlg): KeyEncryptionAlg {
  if (override) return override;
  if (isJoseHpkeAlg(jwk.alg) && jwk.alg.endsWith("-KE")) return jwk.alg as KeyEncryptionAlg;
  const integrated = DEFAULT_INTEGRATED_ALG_FOR_CRV[jwk.crv as SuiteParams["crv"]];
  if (!integrated) throw new Error(`Cannot resolve a Key Encryption algorithm for crv=${jwk.crv}`);
  return `${integrated}-KE` as KeyEncryptionAlg;
}

/**
 * Recipient_structure used as the HPKE `info` for Key Encryption (Section 6.1):
 *   ASCII("JOSE-HPKE rcpt") || 0xFF || ASCII(enc) || 0xFF || recipient_extra_info
 */
export function recipientInfo(enc: string, extra: Uint8Array = new Uint8Array()): Uint8Array {
  const label = encoder.encode("JOSE-HPKE rcpt");
  const encBytes = encoder.encode(enc);
  const out = new Uint8Array(label.length + 1 + encBytes.length + 1 + extra.length);
  let offset = 0;
  out.set(label, offset);
  offset += label.length;
  out[offset++] = 0xff;
  out.set(encBytes, offset);
  offset += encBytes.length;
  out[offset++] = 0xff;
  out.set(extra, offset);
  return out;
}

/** AAD for the content AEAD (identical rule to Integrated, Section 7.1 step 15). */
function contentAad(encodedProtected: string, encodedAad?: string): Uint8Array {
  const value =
    encodedAad === undefined ? encodedProtected : `${encodedProtected}.${encodedAad}`;
  return encoder.encode(value);
}

/** Encrypt `plaintext` to a recipient public JWK using Key Encryption. */
export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicJwk: Jwk,
  options: KeyEncryptionEncryptOptions = {},
): Promise<HpkeKeyEncryptionJwe> {
  const alg = resolveKeyEncryptionAlg(recipientPublicJwk, options.alg);
  const enc = options.enc ?? DEFAULT_ENC[alg];
  if (!isJweEnc(enc)) throw new Error(`Unsupported content-encryption algorithm: ${enc}`);

  // HPKE wraps the CEK. Its `info` binds the content-encryption algorithm; its
  // `aad` is the empty octet sequence. This does not depend on the protected
  // header, so `ek` can be placed in the header afterwards.
  const cek = generateCek(enc);
  const suite = cipherSuiteForAlg(alg);
  const publicKey = await importPublicKey(alg, recipientPublicJwk);
  const { encapsulatedSecret, ciphertext: wrappedCek } = await suite.Seal(publicKey, cek, {
    info: recipientInfo(enc),
  });

  const { alg: _a, enc: _e, ek: _k, ...extra } = (options.protectedHeader ?? {}) as Record<
    string,
    unknown
  >;
  const header = { alg, enc, ...extra, ek: base64url.encode(encapsulatedSecret) };
  const encodedProtected = base64url.encode(encoder.encode(JSON.stringify(header)));
  const encodedAad = options.aad ? base64url.encode(options.aad) : undefined;

  const { iv, ciphertext, tag } = await contentEncrypt(
    enc,
    cek,
    plaintext,
    contentAad(encodedProtected, encodedAad),
  );

  const jwe: HpkeKeyEncryptionJwe = {
    protected: encodedProtected,
    encrypted_key: base64url.encode(wrappedCek),
    iv: base64url.encode(iv),
    ciphertext: base64url.encode(ciphertext),
    tag: base64url.encode(tag),
  };
  if (encodedAad !== undefined) jwe.aad = encodedAad;
  return jwe;
}

/** Decrypt a JSON-serialized Key Encryption HPKE JWE with a recipient private JWK. */
export async function decrypt(
  jwe: HpkeKeyEncryptionJwe,
  recipientPrivateJwk: Jwk,
): Promise<Uint8Array> {
  const header = JSON.parse(new TextDecoder().decode(base64url.decode(jwe.protected))) as {
    alg?: string;
    enc?: string;
    ek?: string;
  };

  if (!isJoseHpkeAlg(header.alg) || !header.alg.endsWith("-KE")) {
    throw new Error(`Not a Key Encryption HPKE alg: ${header.alg}`);
  }
  if (!isJweEnc(header.enc)) {
    throw new Error(`Missing or unsupported "enc" in protected header: ${header.enc}`);
  }
  if (!header.ek) {
    throw new Error('Key Encryption JWE is missing the "ek" header parameter');
  }
  const alg = header.alg as KeyEncryptionAlg;
  const enc = header.enc;

  const suite = cipherSuiteForAlg(alg);
  const keyPair = await importPrivateKey(alg, recipientPrivateJwk);
  const cek = await suite.Open(
    keyPair,
    base64url.decode(header.ek),
    base64url.decode(jwe.encrypted_key),
    { info: recipientInfo(enc) },
  );

  return contentDecrypt(
    enc,
    cek,
    base64url.decode(jwe.iv),
    base64url.decode(jwe.ciphertext),
    base64url.decode(jwe.tag),
    contentAad(jwe.protected, jwe.aad),
  );
}
