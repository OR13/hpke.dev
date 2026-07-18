import { decode, Tag } from "cbor2";
import * as integrated from "./encrypt0";
import * as keyEncryption from "./keyEncryption";
import type { Jwk } from "./keys";
import { isCoseHpkeAlg, type CoseHpkeAlg } from "./suites";
import type { CoseAeadAlg } from "./contentEncryption";

export type CoseMode = "integrated" | "keyEncryption";

const COSE_ENCRYPT0_TAG = 16;
const COSE_ENCRYPT_TAG = 96;
const HEADER_ALG = 1;

/** Detect the COSE HPKE mode from the CBOR tag (16 = Encrypt0, 96 = Encrypt). */
export function coseMode(message: Uint8Array): CoseMode {
  const decoded = decode(message) as unknown;
  if (decoded instanceof Tag && decoded.tag === COSE_ENCRYPT_TAG) return "keyEncryption";
  return "integrated";
}

/** Read the HPKE algorithm id from a COSE HPKE message (either mode). */
export function readAlg(message: Uint8Array): CoseHpkeAlg | undefined {
  const decoded = decode(message) as unknown;
  const tag = decoded instanceof Tag ? decoded.tag : undefined;
  const body = decoded instanceof Tag ? decoded.contents : decoded;
  if (!Array.isArray(body)) return undefined;

  // Key Encryption: alg lives in the first recipient's protected header.
  const protectedBstr =
    tag === COSE_ENCRYPT_TAG
      ? (Array.isArray(body[3]) && Array.isArray(body[3][0]) ? body[3][0][0] : undefined)
      : body[0];
  if (!(protectedBstr instanceof Uint8Array)) return undefined;

  const map = (
    protectedBstr.length ? decode(protectedBstr) : new Map()
  ) as Map<number, unknown>;
  const alg = map.get(HEADER_ALG);
  return isCoseHpkeAlg(alg) ? alg : undefined;
}

export type UnifiedCoseEncryptOptions = {
  /** Which mode to use; defaults to Integrated (COSE_Encrypt0). */
  mode?: CoseMode;
  alg?: CoseHpkeAlg;
  /** Content-encryption algorithm (Key Encryption only). */
  enc?: CoseAeadAlg;
  externalAad?: Uint8Array;
};

export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicJwk: Jwk,
  options: UnifiedCoseEncryptOptions = {},
): Promise<Uint8Array> {
  if (options.mode === "keyEncryption") {
    return keyEncryption.encrypt(plaintext, recipientPublicJwk, {
      alg: options.alg,
      enc: options.enc,
      externalAad: options.externalAad,
    });
  }
  return integrated.encrypt(plaintext, recipientPublicJwk, {
    alg: options.alg,
    externalAad: options.externalAad,
  });
}

export async function decrypt(
  message: Uint8Array,
  recipientPrivateJwk: Jwk,
  options: { externalAad?: Uint8Array } = {},
): Promise<Uint8Array> {
  return coseMode(message) === "keyEncryption"
    ? keyEncryption.decrypt(message, recipientPrivateJwk, options)
    : integrated.decrypt(message, recipientPrivateJwk, options);
}
