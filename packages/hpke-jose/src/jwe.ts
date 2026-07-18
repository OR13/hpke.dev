import { base64url } from "jose";
import * as integrated from "./integrated";
import * as keyEncryption from "./keyEncryption";
import type { Jwk } from "./keys";
import type { IntegratedAlg, KeyEncryptionAlg } from "./suites";
import type { JweEnc } from "./contentEncryption";

/** Either of the two HPKE JWE encryption modes the draft defines. */
export type HpkeJwe = integrated.HpkeIntegratedJwe | keyEncryption.HpkeKeyEncryptionJwe;

export type HpkeMode = "integrated" | "keyEncryption";

export type UnifiedEncryptOptions = {
  /** Which draft mode to use; defaults to Integrated Encryption. */
  mode?: HpkeMode;
  /** Algorithm override (Integrated or Key Encryption label). */
  alg?: IntegratedAlg | KeyEncryptionAlg;
  /** Content-encryption algorithm (Key Encryption only). */
  enc?: JweEnc;
  protectedHeader?: Record<string, unknown>;
  aad?: Uint8Array;
};

function readAlg(jwe: HpkeJwe): string | undefined {
  const header = JSON.parse(new TextDecoder().decode(base64url.decode(jwe.protected)));
  return typeof header.alg === "string" ? header.alg : undefined;
}

/** Detect which mode a JWE uses from its protected header `alg`. */
export function jweMode(jwe: HpkeJwe): HpkeMode {
  return readAlg(jwe)?.endsWith("-KE") ? "keyEncryption" : "integrated";
}

/**
 * Encrypt to a recipient public JWK, choosing the mode via `options.mode`
 * (default: Integrated Encryption).
 */
export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicJwk: Jwk,
  options: UnifiedEncryptOptions = {},
): Promise<HpkeJwe> {
  if (options.mode === "keyEncryption") {
    return keyEncryption.encrypt(plaintext, recipientPublicJwk, {
      alg: options.alg as KeyEncryptionAlg | undefined,
      enc: options.enc,
      protectedHeader: options.protectedHeader,
      aad: options.aad,
    });
  }
  return integrated.encrypt(plaintext, recipientPublicJwk, {
    alg: options.alg as IntegratedAlg | undefined,
    protectedHeader: options.protectedHeader,
    aad: options.aad,
  });
}

/** Decrypt either mode, dispatching on the protected header `alg`. */
export async function decrypt(jwe: HpkeJwe, recipientPrivateJwk: Jwk): Promise<Uint8Array> {
  return jweMode(jwe) === "keyEncryption"
    ? keyEncryption.decrypt(jwe as keyEncryption.HpkeKeyEncryptionJwe, recipientPrivateJwk)
    : integrated.decrypt(jwe as integrated.HpkeIntegratedJwe, recipientPrivateJwk);
}
