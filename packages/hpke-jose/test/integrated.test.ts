import { describe, expect, test } from "bun:test";
import {
  generateKeyPair,
  encrypt,
  decrypt,
  toCompact,
  fromCompact,
  publicFromPrivate,
  type IntegratedAlg,
} from "../src/index";
import { base64url } from "jose";

const utf8 = (s: string) => new TextEncoder().encode(s);
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b);

// P-256 based suites are supported by Web Crypto in every target runtime.
const ALGS: IntegratedAlg[] = ["HPKE-0", "HPKE-7"];

describe("HPKE Integrated Encryption (draft-ietf-jose-hpke-encrypt-22)", () => {
  for (const alg of ALGS) {
    test(`${alg}: round-trips a message`, async () => {
      const { publicKeyJwk, privateKeyJwk } = await generateKeyPair(alg);
      const message = "The Fellowship of the Ring";
      const jwe = await encrypt(utf8(message), publicKeyJwk, { alg });
      const plaintext = await decrypt(jwe, privateKeyJwk);
      expect(fromUtf8(plaintext)).toBe(message);
    });

    test(`${alg}: produces a spec-shaped Integrated JWE`, async () => {
      const { publicKeyJwk } = await generateKeyPair(alg);
      const jwe = await encrypt(utf8("hi"), publicKeyJwk, { alg });

      // Integrated Encryption: empty iv/tag, no enc, ek in encrypted_key.
      expect(jwe.iv).toBe("");
      expect(jwe.tag).toBe("");
      const header = JSON.parse(fromUtf8(base64url.decode(jwe.protected)));
      expect(header.alg).toBe(alg);
      expect(header.enc).toBeUndefined();
      expect(jwe.encrypted_key.length).toBeGreaterThan(0);
      expect(jwe.ciphertext.length).toBeGreaterThan(0);
    });
  }

  test("carries kid in the protected header", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
    const jwe = await encrypt(utf8("with kid"), publicKeyJwk, {
      protectedHeader: { kid: publicKeyJwk.kid },
    });
    const header = JSON.parse(fromUtf8(base64url.decode(jwe.protected)));
    expect(header.kid).toBe(publicKeyJwk.kid);
    expect(fromUtf8(await decrypt(jwe, privateKeyJwk))).toBe("with kid");
  });

  test("binds JWE AAD into the HPKE aad", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
    const aad = utf8("bound-metadata");
    const jwe = await encrypt(utf8("secret"), publicKeyJwk, { aad });
    expect(jwe.aad).toBe(base64url.encode(aad));
    expect(fromUtf8(await decrypt(jwe, privateKeyJwk))).toBe("secret");

    // Tampering with the AAD must break decryption.
    const tampered = { ...jwe, aad: base64url.encode(utf8("other-metadata")) };
    await expect(decrypt(tampered, privateKeyJwk)).rejects.toThrow();
  });

  test("round-trips through Compact Serialization", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
    const jwe = await encrypt(utf8("compact me"), publicKeyJwk);
    const compact = toCompact(jwe);
    expect(compact.split(".")).toHaveLength(5);
    const restored = fromCompact(compact);
    expect(fromUtf8(await decrypt(restored, privateKeyJwk))).toBe("compact me");
  });

  test("fails to decrypt with the wrong key", async () => {
    const alice = await generateKeyPair("HPKE-0");
    const mallory = await generateKeyPair("HPKE-0");
    const jwe = await encrypt(utf8("for alice"), alice.publicKeyJwk);
    await expect(decrypt(jwe, mallory.privateKeyJwk)).rejects.toThrow();
  });

  test("fails to decrypt tampered ciphertext", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
    const jwe = await encrypt(utf8("do not tamper"), publicKeyJwk);
    const bytes = base64url.decode(jwe.ciphertext);
    bytes[0] ^= 0xff;
    const tampered = { ...jwe, ciphertext: base64url.encode(bytes) };
    await expect(decrypt(tampered, privateKeyJwk)).rejects.toThrow();
  });

  test("publicFromPrivate strips private material", async () => {
    const { privateKeyJwk } = await generateKeyPair("HPKE-0");
    const pub = publicFromPrivate(privateKeyJwk);
    expect(pub.d).toBeUndefined();
    expect(pub.x).toBe(privateKeyJwk.x);
  });
});
