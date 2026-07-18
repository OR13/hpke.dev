import type { Key, KeyPair } from "hpke";
import {
  cipherSuiteForAlg,
  paramsForAlg,
  DEFAULT_ALG_FOR_CRV,
  type CoseHpkeAlg,
  type Crv,
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

/** base64url → bytes (works in browser, Bun, and Node via atob). */
function b64uToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function fixedLength(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length === length) return bytes;
  if (bytes.length > length) {
    throw new Error(`coordinate is ${bytes.length} bytes, expected at most ${length}`);
  }
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

/** Uncompressed EC point (0x04 || x || y) or raw OKP octet string. */
export function serializePublicKeyJwk(jwk: Jwk, params: SuiteParams): Uint8Array {
  if (!jwk.x) throw new Error('public JWK is missing "x"');
  const x = fixedLength(b64uToBytes(jwk.x), params.coordinateLength);
  if (params.kty === "OKP") return x;
  if (!jwk.y) throw new Error('EC public JWK is missing "y"');
  const y = fixedLength(b64uToBytes(jwk.y), params.coordinateLength);
  const out = new Uint8Array(1 + x.length + y.length);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 1 + x.length);
  return out;
}

export function serializePrivateKeyJwk(jwk: Jwk, params: SuiteParams): Uint8Array {
  if (!jwk.d) throw new Error('private JWK is missing "d"');
  return fixedLength(b64uToBytes(jwk.d), params.coordinateLength);
}

export async function importPublicKey(alg: CoseHpkeAlg, jwk: Jwk): Promise<Key> {
  const suite = cipherSuiteForAlg(alg);
  return suite.DeserializePublicKey(serializePublicKeyJwk(jwk, paramsForAlg(alg)));
}

/** Import a private JWK as a KeyPair (public coords come from the JWK). */
export async function importPrivateKey(alg: CoseHpkeAlg, jwk: Jwk): Promise<KeyPair> {
  const suite = cipherSuiteForAlg(alg);
  const params = paramsForAlg(alg);
  const [privateKey, publicKey] = await Promise.all([
    suite.DeserializePrivateKey(serializePrivateKeyJwk(jwk, params), false),
    suite.DeserializePublicKey(serializePublicKeyJwk(jwk, params)),
  ]);
  return { publicKey, privateKey };
}

/** Resolve a COSE HPKE algorithm from a recipient JWK (by curve). */
export function resolveAlg(jwk: Jwk): CoseHpkeAlg {
  const alg = DEFAULT_ALG_FOR_CRV[jwk.crv as Crv];
  if (!alg) throw new Error(`Cannot resolve a COSE HPKE algorithm for crv=${jwk.crv}`);
  return alg;
}

/** Generate a recipient key pair (JWKs) using Web Crypto — handy for tests/CLI. */
export async function generateKeyPair(
  alg: CoseHpkeAlg = 35,
): Promise<{ publicKeyJwk: Jwk; privateKeyJwk: Jwk }> {
  const params = paramsForAlg(alg);
  const algorithm =
    params.kty === "EC" ? { name: "ECDH", namedCurve: params.crv } : { name: params.crv };
  const kp = (await crypto.subtle.generateKey(algorithm as EcKeyGenParams, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const privateKeyJwk = (await crypto.subtle.exportKey("jwk", kp.privateKey)) as Jwk;
  const { d: _d, ...publicKeyJwk } = privateKeyJwk;
  return { publicKeyJwk: publicKeyJwk as Jwk, privateKeyJwk };
}

export function publicFromPrivate(jwk: Jwk): Jwk {
  const { d: _d, ...pub } = jwk;
  return pub as Jwk;
}
