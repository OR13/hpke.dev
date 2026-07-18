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
 * COSE HPKE Integrated Encryption algorithm identifiers
 * (draft-ietf-cose-hpke-26, Section 7.2).
 *
 * Values are the draft's assumed integer registrations. HPKE-0 (35) uses the
 * same ciphersuite as JOSE HPKE-0: DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-128-GCM.
 */
export const COSE_HPKE_ALG = {
  "HPKE-0": 35,
  "HPKE-1": 37,
  "HPKE-2": 39,
  "HPKE-3": 41,
  "HPKE-4": 42,
  "HPKE-5": 43,
  "HPKE-6": 44,
  "HPKE-7": 45,
} as const;

export type CoseHpkeAlgLabel = keyof typeof COSE_HPKE_ALG;
export type CoseHpkeAlg = (typeof COSE_HPKE_ALG)[CoseHpkeAlgLabel];

export type Crv = "P-256" | "P-384" | "P-521" | "X25519" | "X448";

export type SuiteParams = {
  label: CoseHpkeAlgLabel;
  kty: "EC" | "OKP";
  crv: Crv;
  coordinateLength: number;
  KEM: KEMFactory;
  KDF: KDFFactory;
  AEAD: AEADFactory;
};

const KEMS: Record<Crv, Pick<SuiteParams, "kty" | "crv" | "coordinateLength" | "KEM">> = {
  "P-256": { kty: "EC", crv: "P-256", coordinateLength: 32, KEM: KEM_DHKEM_P256_HKDF_SHA256 },
  "P-384": { kty: "EC", crv: "P-384", coordinateLength: 48, KEM: KEM_DHKEM_P384_HKDF_SHA384 },
  "P-521": { kty: "EC", crv: "P-521", coordinateLength: 66, KEM: KEM_DHKEM_P521_HKDF_SHA512 },
  X25519: { kty: "OKP", crv: "X25519", coordinateLength: 32, KEM: KEM_DHKEM_X25519_HKDF_SHA256 },
  X448: { kty: "OKP", crv: "X448", coordinateLength: 56, KEM: KEM_DHKEM_X448_HKDF_SHA512 },
};

/** Registry keyed by the integer COSE algorithm identifier. */
export const SUITE_PARAMS: Record<CoseHpkeAlg, SuiteParams> = {
  35: { label: "HPKE-0", ...KEMS["P-256"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_128_GCM },
  37: { label: "HPKE-1", ...KEMS["P-384"], KDF: KDF_HKDF_SHA384, AEAD: AEAD_AES_256_GCM },
  39: { label: "HPKE-2", ...KEMS["P-521"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_AES_256_GCM },
  41: { label: "HPKE-3", ...KEMS["X25519"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_128_GCM },
  42: { label: "HPKE-4", ...KEMS["X25519"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_ChaCha20Poly1305 },
  43: { label: "HPKE-5", ...KEMS["X448"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_AES_256_GCM },
  44: { label: "HPKE-6", ...KEMS["X448"], KDF: KDF_HKDF_SHA512, AEAD: AEAD_ChaCha20Poly1305 },
  45: { label: "HPKE-7", ...KEMS["P-256"], KDF: KDF_HKDF_SHA256, AEAD: AEAD_AES_256_GCM },
};

/** Canonical Integrated algorithm per curve. */
export const DEFAULT_ALG_FOR_CRV: Record<Crv, CoseHpkeAlg> = {
  "P-256": 35,
  "P-384": 37,
  "P-521": 39,
  X25519: 41,
  X448: 43,
};

const suiteCache = new Map<CoseHpkeAlg, CipherSuite>();

export function isCoseHpkeAlg(alg: unknown): alg is CoseHpkeAlg {
  return typeof alg === "number" && alg in SUITE_PARAMS;
}

export function paramsForAlg(alg: CoseHpkeAlg): SuiteParams {
  const params = SUITE_PARAMS[alg];
  if (!params) throw new Error(`Unsupported COSE HPKE algorithm: ${alg}`);
  return params;
}

export function cipherSuiteForAlg(alg: CoseHpkeAlg): CipherSuite {
  let suite = suiteCache.get(alg);
  if (!suite) {
    const p = paramsForAlg(alg);
    suite = new CipherSuite(p.KEM, p.KDF, p.AEAD);
    suiteCache.set(alg, suite);
  }
  return suite;
}
