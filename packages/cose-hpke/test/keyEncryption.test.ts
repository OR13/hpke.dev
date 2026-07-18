import { describe, expect, test } from "bun:test";
import { decode, Tag } from "cbor2";
import {
  generateKeyPair,
  encrypt,
  decrypt,
  coseMode,
  readAlg,
  keyEncryption,
  COSE_HPKE_KE_ALG,
  type CoseAeadAlg,
} from "../src/index";

const utf8 = (s: string) => new TextEncoder().encode(s);
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b);

describe("COSE HPKE Key Encryption (draft-ietf-cose-hpke-26)", () => {
  const encs: CoseAeadAlg[] = [1, 3]; // A128GCM, A256GCM
  for (const enc of encs) {
    test(`HPKE-0-KE / content-alg ${enc}: round-trips`, async () => {
      const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
      const message = "The Council of Elrond";
      const bytes = await keyEncryption.encrypt(utf8(message), publicKeyJwk, {
        alg: COSE_HPKE_KE_ALG["HPKE-0-KE"],
        enc,
      });
      expect(fromUtf8(await keyEncryption.decrypt(bytes, privateKeyJwk))).toBe(message);
    });
  }

  test("produces a spec-shaped tagged COSE_Encrypt", async () => {
    const { publicKeyJwk } = await generateKeyPair();
    const bytes = await keyEncryption.encrypt(utf8("hi"), publicKeyJwk, { alg: 46 });

    const tagged = decode(bytes) as Tag;
    expect(tagged).toBeInstanceOf(Tag);
    expect(tagged.tag).toBe(96);

    const [bodyProtected, bodyUnprotected, ciphertext, recipients] = tagged.contents as [
      Uint8Array,
      Map<number, unknown>,
      Uint8Array,
      unknown[],
    ];
    // body protected: { 1: enc }, unprotected: { 5: iv }
    expect((decode(bodyProtected) as Map<number, unknown>).get(1)).toBe(1); // A128GCM
    expect(bodyUnprotected.get(5)).toBeInstanceOf(Uint8Array);
    expect(ciphertext).toBeInstanceOf(Uint8Array);

    // recipient: [ protected{1:46}, unprotected{-4:ek}, encrypted_key ]
    const [rProtected, rUnprotected, encryptedKey] = recipients[0] as [
      Uint8Array,
      Map<number, unknown>,
      Uint8Array,
    ];
    expect((decode(rProtected) as Map<number, unknown>).get(1)).toBe(46);
    expect(rUnprotected.get(-4)).toBeInstanceOf(Uint8Array);
    expect(encryptedKey).toBeInstanceOf(Uint8Array);

    expect(readAlg(bytes)).toBe(46);
  });

  test("binds external AAD", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();
    const externalAad = utf8("ctx");
    const bytes = await keyEncryption.encrypt(utf8("secret"), publicKeyJwk, { externalAad });
    expect(fromUtf8(await keyEncryption.decrypt(bytes, privateKeyJwk, { externalAad }))).toBe("secret");
    await expect(keyEncryption.decrypt(bytes, privateKeyJwk)).rejects.toThrow();
  });

  test("fails with the wrong key and on tampered ciphertext", async () => {
    const alice = await generateKeyPair();
    const mallory = await generateKeyPair();
    const bytes = await keyEncryption.encrypt(utf8("for alice"), alice.publicKeyJwk);
    await expect(keyEncryption.decrypt(bytes, mallory.privateKeyJwk)).rejects.toThrow();
    const tampered = Uint8Array.from(bytes);
    tampered[tampered.length - 2] ^= 0xff;
    await expect(keyEncryption.decrypt(tampered, alice.privateKeyJwk)).rejects.toThrow();
  });
});

describe("unified COSE encrypt/decrypt dispatch", () => {
  test("Integrated is the default and Key Encryption routes by mode; decrypt auto-detects", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair();

    const int = await encrypt(utf8("integrated"), publicKeyJwk);
    expect(coseMode(int)).toBe("integrated");
    expect(fromUtf8(await decrypt(int, privateKeyJwk))).toBe("integrated");

    const ke = await encrypt(utf8("wrapped"), publicKeyJwk, { mode: "keyEncryption" });
    expect(coseMode(ke)).toBe("keyEncryption");
    expect(fromUtf8(await decrypt(ke, privateKeyJwk))).toBe("wrapped");
  });
});
