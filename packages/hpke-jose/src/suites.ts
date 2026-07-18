import {
  CipherSuite,
  KEM_DHKEM_P256_HKDF_SHA256,
  KEM_DHKEM_P384_HKDF_SHA384,
  KEM_DHKEM_P521_HKDF_SHA512,
  KEM_DHKEM_X25519_HKDF_SHA256,
  KEM_DHKEM_X448_HKDF_SHA512,
  KDF_HKDF_SHA256,
  KDF_HKDF_SHA384,
  KDF_HKDF_SHA512,
  AEAD_AES_128_GCM,
  AEAD_AES_256_GCM,
  AEAD_ChaCha20Poly1305,
  type KEMFactory,
  type KDFFactory,
  type AEADFactory,
} from "hpke";

/**
 * The JOSE HPKE algorithm labels registered by
 * draft-ietf-jose-hpke-encrypt-22.
 *
 * The bare labels (HPKE-0 .. HPKE-7) are Integrated Encryption.
 * The `-KE` labels are Key Encryption. Both use the same underlying
 * HPKE ciphersuite; they differ only in how the JWE is assembled.
 */
export type IntegratedAlg =
  | "HPKE-0"
  | "HPKE-1"
  | "HPKE-2"
  | "HPKE-3"
  | "HPKE-4"
  | "HPKE-5"
  | "HPKE-6"
  | "HPKE-7";

export type KeyEncryptionAlg =
  | "HPKE-0-KE"
  | "HPKE-1-KE"
  | "HPKE-2-KE"
  | "HPKE-3-KE"
  | "HPKE-5-KE"
  | "HPKE-7-KE";

export type JoseHpkeAlg = IntegratedAlg | KeyEncryptionAlg;

export type JwkKeyType = "EC" | "OKP";

export type SuiteParams = {
  /** JWK `kty` for keys used with this suite. */
  kty: JwkKeyType;
  /** JWK `crv` for keys used with this suite. */
  crv: "P-256" | "P-384" | "P-521" | "X25519" | "X448";
  /** Length in bytes of a single EC coordinate / OKP key. */
  coordinateLength: number;
  KEM: KEMFactory;
  KDF: KDFFactory;
  AEAD: AEADFactory;
};

/**
 * KEM parameters shared across every algorithm using that curve.
 */
const KEMS: Record<
  SuiteParams["crv"],
  Pick<SuiteParams, "kty" | "crv" | "coordinateLength" | "KEM">
> = {
  "P-256": { kty: "EC", crv: "P-256", coordinateLength: 32, KEM: KEM_DHKEM_P256_HKDF_SHA256 },
  "P-384": { kty: "EC", crv: "P-384", coordinateLength: 48, KEM: KEM_DHKEM_P384_HKDF_SHA384 },
  "P-521": { kty: "EC", crv: "P-521", coordinateLength: 66, KEM: KEM_DHKEM_P521_HKDF_SHA512 },
  X25519: { kty: "OKP", crv: "X25519", coordinateLength: 32, KEM: KEM_DHKEM_X25519_HKDF_SHA256 },
  X448: { kty: "OKP", crv: "X448", coordinateLength: 56, KEM: KEM_DHKEM_X448_HKDF_SHA512 },
};

/**
 * The full draft-22 integrated + key-encryption registration tables.
 * `-KE` variants intentionally share a base params entry with their bare
 * counterparts (same ciphersuite, different JWE assembly).
 */
export const SUITE_PARAMS: Record<JoseHpkeAlg, SuiteParams> = {
  "HPKE-0": { ...KEMS["P-256"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_128_GCM },
  "HPKE-1": { ...KEMS["P-384"], KDF: KDF_HKDF_SHA384, AEAD: AEAD_AES_256_GCM },
  "HPKE-2": { ...KEMS["P-521"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_AES_256_GCM },
  "HPKE-3": { ...KEMS["X25519"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_128_GCM },
  "HPKE-4": { ...KEMS["X25519"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_ChaCha20Poly1305 },
  "HPKE-5": { ...KEMS["X448"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_AES_256_GCM },
  "HPKE-6": { ...KEMS["X448"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_ChaCha20Poly1305 },
  "HPKE-7": { ...KEMS["P-256"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_256_GCM },
  "HPKE-0-KE": { ...KEMS["P-256"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_128_GCM },
  "HPKE-1-KE": { ...KEMS["P-384"], KDF: KDF_HKDF_SHA384, AEAD: AEAD_AES_256_GCM },
  "HPKE-2-KE": { ...KEMS["P-521"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_AES_256_GCM },
  "HPKE-3-KE": { ...KEMS["X25519"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_128_GCM },
  "HPKE-5-KE": { ...KEMS["X448"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_AES_256_GCM },
  "HPKE-7-KE": { ...KEMS["P-256"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_256_GCM },
};

/** Maps a JWK curve to the canonical Integrated algorithm label. */
export const DEFAULT_INTEGRATED_ALG_FOR_CRV: Record<SuiteParams["crv"], IntegratedAlg> = {
  "P-256": "HPKE-0",
  "P-384": "HPKE-1",
  "P-521": "HPKE-2",
  X25519: "HPKE-3",
  X448: "HPKE-5",
};

const suiteCache = new Map<JoseHpkeAlg, CipherSuite>();

export function isJoseHpkeAlg(alg: unknown): alg is JoseHpkeAlg {
  return typeof alg === "string" && alg in SUITE_PARAMS;
}

export function paramsForAlg(alg: JoseHpkeAlg): SuiteParams {
  const params = SUITE_PARAMS[alg];
  if (!params) throw new Error(`Unsupported JOSE HPKE algorithm: ${alg}`);
  return params;
}

/** Returns a cached panva/hpke CipherSuite for the given algorithm label. */
export function cipherSuiteForAlg(alg: JoseHpkeAlg): CipherSuite {
  let suite = suiteCache.get(alg);
  if (!suite) {
    const params = paramsForAlg(alg);
    suite = new CipherSuite(params.KEM, params.KDF, params.AEAD);
    suiteCache.set(alg, suite);
  }
  return suite;
}
