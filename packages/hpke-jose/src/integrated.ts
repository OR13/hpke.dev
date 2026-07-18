import { base64url } from "jose";
import { cipherSuiteForAlg, isJoseHpkeAlg, type IntegratedAlg } from "./suites";
import { importPrivateKey, importPublicKey, resolveAlg, type Jwk } from "./keys";

const encoder = new TextEncoder();

/**
 * JWE JSON Serialization for HPKE Integrated Encryption
 * (draft-ietf-jose-hpke-encrypt-22, Section 5).
 *
 * For Integrated Encryption:
 *  - the protected header carries `alg` (an HPKE-N label) and MUST NOT carry `enc`
 *  - the JWE Encrypted Key is the HPKE encapsulated secret
 *  - the ciphertext is the HPKE Seal output (which already includes the AEAD tag)
 *  - the JWE Initialization Vector and Authentication Tag are empty
 */
export type HpkeIntegratedJwe = {
  protected: string;
  encrypted_key: string;
  ciphertext: string;
  iv: "";
  tag: "";
  aad?: string;
};

export type EncryptOptions = {
  /** Override the algorithm; defaults to the recipient key's `alg`/curve. */
  alg?: IntegratedAlg;
  /** Additional protected header parameters (e.g. `kid`). */
  protectedHeader?: Record<string, unknown>;
  /** Optional JWE AAD, integrity-protected but not encrypted. */
  aad?: Uint8Array;
};

function toProtectedHeader(alg: IntegratedAlg, extra: Record<string, unknown> = {}) {
  // `enc` MUST NOT be present for Integrated Encryption.
  const { enc: _enc, ...rest } = extra as { enc?: unknown };
  return { alg, ...rest };
}

/**
 * Construct the HPKE `aad` input from the encoded protected header and the
 * optional JWE AAD, per Section 7.1 step 15:
 *   ASCII(Encoded Protected Header)
 *   ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))   [when AAD present]
 */
function hpkeAad(encodedProtected: string, encodedAad?: string): Uint8Array {
  const value =
    encodedAad === undefined ? encodedProtected : `${encodedProtected}.${encodedAad}`;
  return encoder.encode(value);
}

/** Encrypt `plaintext` to a recipient public JWK, returning a JSON-serialized JWE. */
export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicJwk: Jwk,
  options: EncryptOptions = {},
): Promise<HpkeIntegratedJwe> {
  const resolved = options.alg ?? resolveAlg(recipientPublicJwk);
  if (resolved.endsWith("-KE")) {
    throw new Error(`${resolved} is a Key Encryption algorithm; use the key-encryption API`);
  }
  const alg = resolved as IntegratedAlg;

  const header = toProtectedHeader(alg, options.protectedHeader);
  const encodedProtected = base64url.encode(encoder.encode(JSON.stringify(header)));
  const encodedAad = options.aad ? base64url.encode(options.aad) : undefined;

  const suite = cipherSuiteForAlg(alg);
  const publicKey = await importPublicKey(alg, recipientPublicJwk);
  const { encapsulatedSecret, ciphertext } = await suite.Seal(publicKey, plaintext, {
    aad: hpkeAad(encodedProtected, encodedAad),
    // HPKE `info` defaults to the empty octet sequence for Integrated Encryption.
  });

  const jwe: HpkeIntegratedJwe = {
    protected: encodedProtected,
    encrypted_key: base64url.encode(encapsulatedSecret),
    ciphertext: base64url.encode(ciphertext),
    iv: "",
    tag: "",
  };
  if (encodedAad !== undefined) jwe.aad = encodedAad;
  return jwe;
}

/** Decrypt a JSON-serialized Integrated HPKE JWE with a recipient private JWK. */
export async function decrypt(
  jwe: HpkeIntegratedJwe,
  recipientPrivateJwk: Jwk,
): Promise<Uint8Array> {
  const header = JSON.parse(
    new TextDecoder().decode(base64url.decode(jwe.protected)),
  ) as { alg?: string; enc?: unknown };

  if (!isJoseHpkeAlg(header.alg)) {
    throw new Error(`Unsupported or missing HPKE alg in protected header: ${header.alg}`);
  }
  if (header.alg.endsWith("-KE")) {
    throw new Error(`${header.alg} is a Key Encryption algorithm; use the key-encryption API`);
  }
  if ("enc" in header && header.enc !== undefined) {
    throw new Error('Integrated Encryption JWE MUST NOT contain "enc"');
  }
  const alg = header.alg as IntegratedAlg;

  const suite = cipherSuiteForAlg(alg);
  const privateKey = await importPrivateKey(alg, recipientPrivateJwk);
  const aad = hpkeAad(jwe.protected, jwe.aad);

  return suite.Open(
    privateKey,
    base64url.decode(jwe.encrypted_key),
    base64url.decode(jwe.ciphertext),
    { aad },
  );
}

/**
 * Compact Serialization for Integrated Encryption:
 *   BASE64URL(Protected) '.' BASE64URL(Encrypted Key) '.' '' '.' BASE64URL(Ciphertext) '.' ''
 * Note: Compact form cannot carry a JWE AAD.
 */
export function toCompact(jwe: HpkeIntegratedJwe): string {
  if (jwe.aad !== undefined) {
    throw new Error("Compact Serialization cannot represent a JWE with AAD");
  }
  return `${jwe.protected}.${jwe.encrypted_key}..${jwe.ciphertext}.`;
}

export function fromCompact(compact: string): HpkeIntegratedJwe {
  const parts = compact.split(".");
  if (parts.length !== 5) {
    throw new Error("Invalid HPKE Compact Serialization");
  }
  const [protectedHeader, encrypted_key, iv, ciphertext, tag] = parts;
  if (iv !== "" || tag !== "") {
    throw new Error("Integrated Encryption Compact JWE must have empty iv and tag");
  }
  return { protected: protectedHeader, encrypted_key, ciphertext, iv: "", tag: "" };
}
