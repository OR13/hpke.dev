import { encode, decode, Tag } from "cbor2";
import { cipherSuiteForAlg, isCoseHpkeAlg, isIntegratedAlg, type CoseHpkeAlg } from "./suites";
import { importPrivateKey, importPublicKey, resolveAlg, type Jwk } from "./keys";

/**
 * COSE HPKE Integrated Encryption with a single recipient
 * (draft-ietf-cose-hpke-26), encoded as a tagged COSE_Encrypt0:
 *
 *   16([ protected, unprotected, ciphertext ])
 *
 * where the protected header carries the HPKE algorithm (`1: alg`), the
 * unprotected header carries the HPKE encapsulated key (`-4: ek`, a bstr), and
 * the ciphertext is the HPKE Seal output. The HPKE `aad` is the CBOR-encoded
 * Enc_structure `["Encrypt0", protected, external_aad]` (RFC 9052 §5.3); the
 * HPKE `info` is empty.
 */
const COSE_ENCRYPT0_TAG = 16;
const HEADER_ALG = 1;
const HEADER_EK = -4;
const EMPTY = new Uint8Array();

function encStructure(protectedBstr: Uint8Array, externalAad: Uint8Array): Uint8Array {
  return encode(["Encrypt0", protectedBstr, externalAad]);
}

export type CoseEncryptOptions = {
  /** Override the COSE HPKE algorithm; defaults to the key's curve. */
  alg?: CoseHpkeAlg;
  /** Externally supplied additional authenticated data (default: empty). */
  externalAad?: Uint8Array;
};

/** Encrypt `plaintext` to a recipient public JWK, returning tagged COSE_Encrypt0 bytes. */
export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicJwk: Jwk,
  options: CoseEncryptOptions = {},
): Promise<Uint8Array> {
  const alg = options.alg ?? resolveAlg(recipientPublicJwk);
  const externalAad = options.externalAad ?? EMPTY;

  const protectedBstr = encode(new Map<number, number>([[HEADER_ALG, alg]]));
  const aad = encStructure(protectedBstr, externalAad);

  const suite = cipherSuiteForAlg(alg);
  const publicKey = await importPublicKey(alg, recipientPublicJwk);
  const { encapsulatedSecret, ciphertext } = await suite.Seal(publicKey, plaintext, { aad });

  const unprotected = new Map<number, Uint8Array>([[HEADER_EK, encapsulatedSecret]]);
  return encode(new Tag(COSE_ENCRYPT0_TAG, [protectedBstr, unprotected, ciphertext]));
}

/** Decrypt a tagged (or untagged) COSE_Encrypt0 HPKE message with a recipient private JWK. */
export async function decrypt(
  message: Uint8Array,
  recipientPrivateJwk: Jwk,
  options: { externalAad?: Uint8Array } = {},
): Promise<Uint8Array> {
  const externalAad = options.externalAad ?? EMPTY;

  const decoded = decode(message) as unknown;
  let body: unknown;
  if (decoded instanceof Tag) {
    if (decoded.tag !== COSE_ENCRYPT0_TAG) {
      throw new Error(`expected COSE_Encrypt0 tag ${COSE_ENCRYPT0_TAG}, got ${decoded.tag}`);
    }
    body = decoded.contents;
  } else {
    body = decoded;
  }
  if (!Array.isArray(body) || body.length !== 3) {
    throw new Error("invalid COSE_Encrypt0 structure");
  }
  const [protectedBstr, unprotected, ciphertext] = body as [Uint8Array, Map<number, unknown>, Uint8Array];

  const protectedMap = (
    protectedBstr.length ? decode(protectedBstr) : new Map()
  ) as Map<number, unknown>;
  const alg = protectedMap.get(HEADER_ALG);
  if (typeof alg !== "number" || !isIntegratedAlg(alg)) {
    throw new Error(`unsupported COSE HPKE Integrated alg: ${String(alg)}`);
  }

  const enc = unprotected.get(HEADER_EK);
  if (!(enc instanceof Uint8Array)) throw new Error('missing "ek" (encapsulated key)');

  const aad = encStructure(protectedBstr, externalAad);
  const suite = cipherSuiteForAlg(alg);
  const keyPair = await importPrivateKey(alg, recipientPrivateJwk);
  return suite.Open(keyPair, enc, ciphertext, { aad });
}

/** Inspect a COSE_Encrypt0 message's algorithm without decrypting. */
export function readAlg(message: Uint8Array): CoseHpkeAlg | undefined {
  const decoded = decode(message) as unknown;
  const body = decoded instanceof Tag ? decoded.contents : decoded;
  if (!Array.isArray(body) || body.length !== 3) return undefined;
  const protectedBstr = body[0] as Uint8Array;
  const protectedMap = (
    protectedBstr.length ? decode(protectedBstr) : new Map()
  ) as Map<number, unknown>;
  const alg = protectedMap.get(HEADER_ALG);
  return isCoseHpkeAlg(alg) ? alg : undefined;
}
