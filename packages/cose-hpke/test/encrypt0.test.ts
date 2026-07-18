import { describe, expect, test } from "bun:test";
import { decode, Tag } from "cbor2";
import {
  generateKeyPair,
  publicFromPrivate,
  encrypt,
  decrypt,
  readAlg,
  COSE_HPKE_ALG,
  type CoseHpkeAlg,
} from "../src/index";

const utf8 = (s: string) => new TextEncoder().encode(s);
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b);

// P-256 suites are supported by Web Crypto in every target runtime.
const ALGS: CoseHpkeAlg[] = [COSE_HPKE_ALG["HPKE-0"], COSE_HPKE_ALG["HPKE-7"]];

describe("COSE HPKE Integrated Encryption (draft-ietf-cose-hpke-26)", () => {
  for (const alg of ALGS) {
    test(`alg ${alg}: round-trips a message`, async () => {
      const { publicKeyJwk, privateKeyJwk } = await generateKeyPair(alg);
      const message = "There and back again";
      const coseBytes = await encrypt(utf8(message), publicKeyJwk, { alg });
      expect(fromUtf8(await decrypt(coseBytes, privateKeyJwk))).toBe(message);
    });
  }

  test("produces a spec-shaped tagged COSE_Encrypt0", async () => {
    const { publicKeyJwk } = await generateKeyPair();
    const bytes = await encrypt(utf8("hi"), publicKeyJwk, { alg: 35 });

    const tagged = decode(bytes);
    expect(tagged).toBeInstanceOf(Tag);
    expect((tagged as Tag).tag).toBe(16);

    const [protectedBstr, unprotected, ciphertext] = (tagged as Tag).contents as [
      Uint8Array,
      Map<number, unknown>,
      Uint8Array,
    ];
    // protected header: { 1: 35 }
    const protectedMap = decode(protectedBstr) as Map<number, unknown>;
    expect(protectedMap.get(1)).toBe(35);
    // unprotected header: { -4: ek } (encapsulated key, bstr)
    expect(unprotected.get(-4)).toBeInstanceOf(Uint8Array);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(readAlg(bytes)).toBe(35);
  });

  test("binds external AAD", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
    const externalAad = utf8("context-42");
    const bytes = await encrypt(utf8("secret"), publicKeyJwk, { externalAad });
    expect(fromUtf8(await decrypt(bytes, privateKeyJwk, { externalAad }))).toBe("secret");
    // wrong / missing external AAD must fail
    await expect(decrypt(bytes, privateKeyJwk)).rejects.toThrow();
  });

  test("fails with the wrong key", async () => {
    const alice = await generateKeyPair();
    const mallory = await generateKeyPair();
    const bytes = await encrypt(utf8("for alice"), alice.publicKeyJwk);
    await expect(decrypt(bytes, mallory.privateKeyJwk)).rejects.toThrow();
  });

  test("fails on tampered ciphertext", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
    const bytes = await encrypt(utf8("do not tamper"), publicKeyJwk);
    const tampered = Uint8Array.from(bytes);
    tampered[tampered.length - 1] ^= 0xff;
    await expect(decrypt(tampered, privateKeyJwk)).rejects.toThrow();
  });

  test("publicFromPrivate strips private material", async () => {
    const { privateKeyJwk } = await generateKeyPair();
    const pub = publicFromPrivate(privateKeyJwk);
    expect(pub.d).toBeUndefined();
    expect(pub.x).toBe(privateKeyJwk.x);
  });
});
