import pako from "pako";
import { base64url } from "jose";
import type { HpkeJwe } from "@hpke-jose";

/**
 * URL fragment scheme for sharing an HPKE JWE inside a link.
 *
 * The payload after the prefix is BASE64URL(gzip(UTF8(JSON JWE))). Reading the
 * label chain outermost-first: it is a `gzip`ped, `base64url`-encoded HPKE JWE
 * (`hpke:jwe`). Nothing after the fragment is sent to the server, so the
 * ciphertext never leaves the browser except in the URL the sender chooses to
 * share.
 *
 *   #gzip:base64url:hpke:jwe:<base64url(gzip(json))>
 */
export const HPKE_JWE_FRAGMENT_PREFIX = "gzip:base64url:hpke:jwe:";

const stripHash = (fragment: string) => fragment.replace(/^#/, "");

export function encodeHpkeJweFragment(jwe: HpkeJwe): string {
  const json = new TextEncoder().encode(JSON.stringify(jwe));
  const gzipped = pako.gzip(json);
  return HPKE_JWE_FRAGMENT_PREFIX + base64url.encode(gzipped);
}

export function isHpkeJweFragment(fragment: string): boolean {
  return stripHash(fragment).startsWith(HPKE_JWE_FRAGMENT_PREFIX);
}

export function decodeHpkeJweFragment(fragment: string): HpkeJwe {
  const value = stripHash(fragment);
  if (!value.startsWith(HPKE_JWE_FRAGMENT_PREFIX)) {
    throw new Error("Not an HPKE JWE URL fragment");
  }
  const encoded = value.slice(HPKE_JWE_FRAGMENT_PREFIX.length);
  const json = pako.ungzip(base64url.decode(encoded), { to: "string" });
  return JSON.parse(json) as HpkeJwe;
}

/**
 * COSE HPKE variant of the same scheme. The payload is the raw
 * tagged COSE_Encrypt0 (binary CBOR), gzipped and base64url-encoded:
 *
 *   #gzip:base64url:hpke:cose:<base64url(gzip(COSE_Encrypt0 bytes))>
 */
export const HPKE_COSE_FRAGMENT_PREFIX = "gzip:base64url:hpke:cose:";

export function encodeHpkeCoseFragment(coseBytes: Uint8Array): string {
  return HPKE_COSE_FRAGMENT_PREFIX + base64url.encode(pako.gzip(coseBytes));
}

export function isHpkeCoseFragment(fragment: string): boolean {
  return stripHash(fragment).startsWith(HPKE_COSE_FRAGMENT_PREFIX);
}

export function decodeHpkeCoseFragment(fragment: string): Uint8Array {
  const value = stripHash(fragment);
  if (!value.startsWith(HPKE_COSE_FRAGMENT_PREFIX)) {
    throw new Error("Not an HPKE COSE URL fragment");
  }
  const encoded = value.slice(HPKE_COSE_FRAGMENT_PREFIX.length);
  return pako.ungzip(base64url.decode(encoded));
}
