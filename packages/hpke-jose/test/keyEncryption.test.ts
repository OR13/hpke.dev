import { describe, expect, test } from "bun:test";
import { base64url } from "jose";
import {
  generateKeyPair,
  keyEncryption,
  encrypt,
  decrypt,
  jweMode,
  type KeyEncryptionAlg,
  type JweEnc,
} from "../src/index";
import { recipientInfo } from "../src/keyEncryption";

const utf8 = (s: string) => new TextEncoder().encode(s);
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b);

describe("HPKE Key Encryption (draft-ietf-jose-hpke-encrypt-22)", () => {
  const cases: { alg: KeyEncryptionAlg; enc: JweEnc }[] = [
    { alg: "HPKE-0-KE", enc: "A128GCM" },
    { alg: "HPKE-0-KE", enc: "A256GCM" },
    { alg: "HPKE-7-KE", enc: "A256GCM" },
  ];

  for (const { alg, enc } of cases) {
    test(`${alg}/${enc}: round-trips a message`, async () => {
      const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
      const message = "One does not simply walk into Mordor";
      const jwe = await keyEncryption.encrypt(utf8(message), publicKeyJwk, { alg, enc });
      expect(fromUtf8(await keyEncryption.decrypt(jwe, privateKeyJwk))).toBe(message);
    });
  }

  test("produces a spec-shaped Key Encryption JWE (ek+enc in header, non-empty iv/tag)", async () => {
    const { publicKeyJwk } = await generateKeyPair("HPKE-0");
    const jwe = await keyEncryption.encrypt(utf8("hi"), publicKeyJwk, { alg: "HPKE-0-KE" });
    const header = JSON.parse(fromUtf8(base64url.decode(jwe.protected)));

    expect(header.alg).toBe("HPKE-0-KE");
    expect(header.enc).toBe("A128GCM");
    expect(typeof header.ek).toBe("string");
    expect(header.ek.length).toBeGreaterThan(0);
    // iv and tag come from the content AEAD and are non-empty (unlike Integrated).
    expect(jwe.iv.length).toBeGreaterThan(0);
    expect(jwe.tag.length).toBeGreaterThan(0);
    expect(jwe.encrypted_key.length).toBeGreaterThan(0);
  });

  test("recipientInfo matches the draft hex for A128GCM", () => {
    // ASCII("JOSE-HPKE rcpt") || 0xFF || ASCII("A128GCM") || 0xFF
    const hex = Buffer.from(recipientInfo("A128GCM")).toString("hex");
    expect(hex).toBe("4a4f53452d48504b452072637074ff4131323847434dff");
  });

  test("carries kid and binds JWE AAD", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
    const aad = utf8("bound");
    const jwe = await keyEncryption.encrypt(utf8("secret"), publicKeyJwk, {
      alg: "HPKE-0-KE",
      protectedHeader: { kid: publicKeyJwk.kid },
      aad,
    });
    const header = JSON.parse(fromUtf8(base64url.decode(jwe.protected)));
    expect(header.kid).toBe(publicKeyJwk.kid);
    expect(jwe.aad).toBe(base64url.encode(aad));
    expect(fromUtf8(await keyEncryption.decrypt(jwe, privateKeyJwk))).toBe("secret");

    const tampered = { ...jwe, aad: base64url.encode(utf8("other")) };
    await expect(keyEncryption.decrypt(tampered, privateKeyJwk)).rejects.toThrow();
  });

  test("fails with the wrong key and on tampered ciphertext", async () => {
    const alice = await generateKeyPair("HPKE-0");
    const mallory = await generateKeyPair("HPKE-0");
    const jwe = await keyEncryption.encrypt(utf8("for alice"), alice.publicKeyJwk, {
      alg: "HPKE-0-KE",
    });
    await expect(keyEncryption.decrypt(jwe, mallory.privateKeyJwk)).rejects.toThrow();

    const bytes = base64url.decode(jwe.ciphertext);
    bytes[0] ^= 0xff;
    const tampered = { ...jwe, ciphertext: base64url.encode(bytes) };
    await expect(keyEncryption.decrypt(tampered, alice.privateKeyJwk)).rejects.toThrow();
  });
});

describe("unified encrypt/decrypt dispatch", () => {
  test("Integrated is the default mode", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
    const jwe = await encrypt(utf8("default"), publicKeyJwk);
    expect(jweMode(jwe)).toBe("integrated");
    expect(fromUtf8(await decrypt(jwe, privateKeyJwk))).toBe("default");
  });

  test("mode: keyEncryption routes to Key Encryption and decrypt auto-detects", async () => {
    const { publicKeyJwk, privateKeyJwk } = await generateKeyPair("HPKE-0");
    const jwe = await encrypt(utf8("wrapped"), publicKeyJwk, { mode: "keyEncryption" });
    expect(jweMode(jwe)).toBe("keyEncryption");
    // decrypt() dispatches purely on the JWE, no mode hint needed.
    expect(fromUtf8(await decrypt(jwe, privateKeyJwk))).toBe("wrapped");
  });
});
