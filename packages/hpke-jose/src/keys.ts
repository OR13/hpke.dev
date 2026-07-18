import { base64url, calculateJwkThumbprintUri } from "jose";
import type { Key, KeyPair } from "hpke";
import {
  cipherSuiteForAlg,
  paramsForAlg,
  DEFAULT_INTEGRATED_ALG_FOR_CRV,
  isJoseHpkeAlg,
  type JoseHpkeAlg,
  type SuiteParams,
} from "./suites";

export type Jwk = {
  kty: string;
  crv: string;
  x?: string;
  y?: string;
  d?: string;
  kid?: string;
  alg?: string;
  [key: string]: unknown;
};

/** Left-pad (or validate) a coordinate to exactly `length` bytes. */
function fixedLength(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length === length) return bytes;
  if (bytes.length > length) {
    throw new Error(`coordinate is ${bytes.length} bytes, expected at most ${length}`);
  }
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

/**
 * Serialize a JWK public key into the raw HPKE public key encoding expected by
 * the KEM (uncompressed EC point `0x04 || x || y`, or the raw OKP octet string).
 */
export function serializePublicKeyJwk(jwk: Jwk, params: SuiteParams): Uint8Array {
  if (!jwk.x) throw new Error('public JWK is missing "x"');
  const x = fixedLength(base64url.decode(jwk.x), params.coordinateLength);
  if (params.kty === "OKP") return x;
  if (!jwk.y) throw new Error('EC public JWK is missing "y"');
  const y = fixedLength(base64url.decode(jwk.y), params.coordinateLength);
  const out = new Uint8Array(1 + x.length + y.length);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 1 + x.length);
  return out;
}

/** Serialize a JWK private key into the raw HPKE private key scalar/octet string. */
export function serializePrivateKeyJwk(jwk: Jwk, params: SuiteParams): Uint8Array {
  if (!jwk.d) throw new Error('private JWK is missing "d"');
  return fixedLength(base64url.decode(jwk.d), params.coordinateLength);
}

/** Import a recipient public JWK into a panva/hpke Key for the given algorithm. */
export async function importPublicKey(alg: JoseHpkeAlg, jwk: Jwk): Promise<Key> {
  const suite = cipherSuiteForAlg(alg);
  return suite.DeserializePublicKey(serializePublicKeyJwk(jwk, paramsForAlg(alg)));
}

/**
 * Import a recipient private JWK into a panva/hpke KeyPair for the given
 * algorithm. A KeyPair (rather than a bare private Key) is used so the KEM can
 * obtain the recipient public key for decapsulation without requiring the
 * imported private key to be extractable.
 */
export async function importPrivateKey(alg: JoseHpkeAlg, jwk: Jwk): Promise<KeyPair> {
  const suite = cipherSuiteForAlg(alg);
  const params = paramsForAlg(alg);
  const [privateKey, publicKey] = await Promise.all([
    suite.DeserializePrivateKey(serializePrivateKeyJwk(jwk, params), false),
    suite.DeserializePublicKey(serializePublicKeyJwk(jwk, params)),
  ]);
  return { publicKey, privateKey };
}

/**
 * Resolve the HPKE algorithm to use for a given recipient JWK. Honors an
 * explicit `alg` on the key when it is a registered label, otherwise derives
 * the canonical Integrated label from the key's curve.
 */
export function resolveAlg(jwk: Jwk): JoseHpkeAlg {
  if (isJoseHpkeAlg(jwk.alg)) return jwk.alg;
  const crv = jwk.crv as SuiteParams["crv"];
  const alg = DEFAULT_INTEGRATED_ALG_FOR_CRV[crv];
  if (!alg) throw new Error(`Cannot resolve a JOSE HPKE algorithm for crv=${jwk.crv}`);
  return alg;
}

/**
 * Generate a fresh recipient key pair (as JWKs) for the given algorithm using
 * Web Crypto, tagged with the algorithm and its JWK thumbprint `kid`.
 */
export async function generateKeyPair(
  alg: JoseHpkeAlg = "HPKE-0",
): Promise<{ publicKeyJwk: Jwk; privateKeyJwk: Jwk }> {
  const params = paramsForAlg(alg);
  const algorithm =
    params.kty === "EC" ? { name: "ECDH", namedCurve: params.crv } : { name: params.crv };
  const usages: KeyUsage[] = ["deriveBits"];
  const keyPair = (await crypto.subtle.generateKey(
    algorithm as EcKeyGenParams,
    true,
    usages,
  )) as CryptoKeyPair;

  const privateKeyJwk = (await crypto.subtle.exportKey("jwk", keyPair.privateKey)) as Jwk;
  const publicKeyJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as Jwk;

  const kid = await calculateJwkThumbprintUri({
    kty: publicKeyJwk.kty,
    crv: publicKeyJwk.crv,
    ...(publicKeyJwk.x ? { x: publicKeyJwk.x } : {}),
    ...(publicKeyJwk.y ? { y: publicKeyJwk.y } : {}),
  } as any);

  return {
    publicKeyJwk: orderJwk({ ...publicKeyJwk, alg, kid }),
    privateKeyJwk: orderJwk({ ...privateKeyJwk, alg, kid }),
  };
}

/** Stable field ordering matching the rest of the hpke.dev demo. */
export function orderJwk(jwk: Jwk): Jwk {
  const { kid, alg, kty, crv, x, y, d } = jwk;
  return JSON.parse(
    JSON.stringify({ kid, alg, kty, crv, x, y, d }),
  ) as Jwk;
}

/** Strip private material, returning the corresponding public JWK. */
export function publicFromPrivate(jwk: Jwk): Jwk {
  const { d, ...pub } = jwk;
  return orderJwk(pub as Jwk);
}
