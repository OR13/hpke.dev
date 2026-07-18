import { encode, decode, Tag } from "cbor2";
import {
  cipherSuiteForAlg,
  isKeyEncryptionAlg,
  DEFAULT_KE_ALG_FOR_CRV,
  type CoseHpkeAlg,
  type Crv,
} from "./suites";
import { importPrivateKey, importPublicKey, type Jwk } from "./keys";
import {
  contentDecrypt,
  contentEncrypt,
  generateCek,
  generateIv,
  isCoseAeadAlg,
  type CoseAeadAlg,
} from "./contentEncryption";

/**
 * COSE HPKE Key Encryption with a single recipient (draft-ietf-cose-hpke-26),
 * encoded as a tagged COSE_Encrypt:
 *
 *   96([ protected, unprotected, ciphertext, [ recipient ] ])
 *
 * The body protected header carries the content-encryption algorithm (`1: enc`),
 * the body unprotected header carries the IV (`5: iv`), and the ciphertext is the
 * content sealed with the CEK. Each recipient is
 * `[ protected{1: HPKE-KE alg}, unprotected{-4: ek}, encrypted_key ]`, where
 * `encrypted_key` is the HPKE Seal of the CEK. The HPKE `aad` is empty and the
 * HPKE `info` is the CBOR Recipient_structure
 * `["HPKE Recipient", enc, recipient_protected, extra]` (Section 3.3.1).
 */
const COSE_ENCRYPT_TAG = 96;
const HEADER_ALG = 1;
const HEADER_IV = 5;
const HEADER_EK = -4;
const EMPTY = new Uint8Array();

const DEFAULT_CONTENT_ALG: Record<number, CoseAeadAlg> = {
  46: 1, // HPKE-0-KE  -> A128GCM
  47: 3, // HPKE-1-KE  -> A256GCM
  48: 3,
  49: 1, // HPKE-3-KE  -> A128GCM
  50: 3,
  51: 3,
  52: 3,
  53: 3, // HPKE-7-KE  -> A256GCM
};

export type CoseKeyEncryptionOptions = {
  /** Override the HPKE Key Encryption algorithm; defaults to the key's curve. */
  alg?: CoseHpkeAlg;
  /** Content-encryption algorithm; defaults per the chosen -KE algorithm. */
  enc?: CoseAeadAlg;
  /** Externally supplied additional authenticated data for layer 0. */
  externalAad?: Uint8Array;
};

export function resolveKeyEncryptionAlg(jwk: Jwk, override?: CoseHpkeAlg): CoseHpkeAlg {
  if (override !== undefined) return override;
  const alg = DEFAULT_KE_ALG_FOR_CRV[jwk.crv as Crv];
  if (!alg) throw new Error(`Cannot resolve a COSE HPKE Key Encryption alg for crv=${jwk.crv}`);
  return alg;
}

/** HPKE info: Recipient_structure ["HPKE Recipient", enc, recipient_protected, extra]. */
function recipientInfo(
  enc: CoseAeadAlg,
  recipientProtected: Uint8Array,
  extra: Uint8Array = EMPTY,
): Uint8Array {
  return encode(["HPKE Recipient", enc, recipientProtected, extra]);
}

/** Layer-0 AAD: Enc_structure ["Encrypt", body_protected, external_aad]. */
function contentAad(bodyProtected: Uint8Array, externalAad: Uint8Array): Uint8Array {
  return encode(["Encrypt", bodyProtected, externalAad]);
}

export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicJwk: Jwk,
  options: CoseKeyEncryptionOptions = {},
): Promise<Uint8Array> {
  const alg = resolveKeyEncryptionAlg(recipientPublicJwk, options.alg);
  if (!isKeyEncryptionAlg(alg)) throw new Error(`${alg} is not a COSE HPKE Key Encryption alg`);
  const enc = options.enc ?? DEFAULT_CONTENT_ALG[alg] ?? 1;
  const externalAad = options.externalAad ?? EMPTY;

  // Wrap a fresh CEK to the recipient with HPKE (aad empty, info = Recipient_structure).
  const cek = generateCek(enc);
  const recipientProtected = encode(new Map<number, number>([[HEADER_ALG, alg]]));
  const suite = cipherSuiteForAlg(alg);
  const publicKey = await importPublicKey(alg, recipientPublicJwk);
  const { encapsulatedSecret, ciphertext: encryptedKey } = await suite.Seal(publicKey, cek, {
    info: recipientInfo(enc, recipientProtected),
  });

  // Encrypt the content with the CEK at layer 0.
  const bodyProtected = encode(new Map<number, number>([[HEADER_ALG, enc]]));
  const iv = generateIv();
  const ciphertext = await contentEncrypt(
    enc,
    cek,
    iv,
    plaintext,
    contentAad(bodyProtected, externalAad),
  );

  const recipient = [
    recipientProtected,
    new Map<number, Uint8Array>([[HEADER_EK, encapsulatedSecret]]),
    encryptedKey,
  ];
  const body = [bodyProtected, new Map<number, Uint8Array>([[HEADER_IV, iv]]), ciphertext, [
    recipient,
  ]];
  return encode(new Tag(COSE_ENCRYPT_TAG, body));
}

export async function decrypt(
  message: Uint8Array,
  recipientPrivateJwk: Jwk,
  options: { externalAad?: Uint8Array } = {},
): Promise<Uint8Array> {
  const externalAad = options.externalAad ?? EMPTY;

  const decoded = decode(message) as unknown;
  const body = (decoded instanceof Tag ? decoded.contents : decoded) as unknown;
  if (decoded instanceof Tag && decoded.tag !== COSE_ENCRYPT_TAG) {
    throw new Error(`expected COSE_Encrypt tag ${COSE_ENCRYPT_TAG}, got ${decoded.tag}`);
  }
  if (!Array.isArray(body) || body.length !== 4) {
    throw new Error("invalid COSE_Encrypt structure");
  }
  const [bodyProtected, bodyUnprotected, ciphertext, recipients] = body as [
    Uint8Array,
    Map<number, unknown>,
    Uint8Array,
    unknown[],
  ];

  const bodyProtectedMap = (
    bodyProtected.length ? decode(bodyProtected) : new Map()
  ) as Map<number, unknown>;
  const enc = bodyProtectedMap.get(HEADER_ALG);
  if (!isCoseAeadAlg(enc)) throw new Error(`unsupported content-encryption alg: ${String(enc)}`);
  const iv = bodyUnprotected.get(HEADER_IV);
  if (!(iv instanceof Uint8Array)) throw new Error("missing IV");

  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error("COSE_Encrypt has no recipients");
  }
  const [recipientProtected, recipientUnprotected, encryptedKey] = recipients[0] as [
    Uint8Array,
    Map<number, unknown>,
    Uint8Array,
  ];
  const recipientProtectedMap = (
    recipientProtected.length ? decode(recipientProtected) : new Map()
  ) as Map<number, unknown>;
  const alg = recipientProtectedMap.get(HEADER_ALG);
  if (!isKeyEncryptionAlg(alg as number)) {
    throw new Error(`unsupported COSE HPKE Key Encryption alg: ${String(alg)}`);
  }
  const ek = recipientUnprotected.get(HEADER_EK);
  if (!(ek instanceof Uint8Array)) throw new Error('missing "ek" (encapsulated key)');

  // Unwrap the CEK, then decrypt the content.
  const suite = cipherSuiteForAlg(alg as CoseHpkeAlg);
  const keyPair = await importPrivateKey(alg as CoseHpkeAlg, recipientPrivateJwk);
  const cek = await suite.Open(keyPair, ek, encryptedKey, {
    info: recipientInfo(enc, recipientProtected),
  });

  return contentDecrypt(enc, cek, iv, ciphertext, contentAad(bodyProtected, externalAad));
}
