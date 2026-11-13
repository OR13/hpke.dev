// Independent upstream vectors pinned to cose-wg/draft-ietf-cose-hpke PR #155,
// commit 8cef948f1d8173ec4a21da61ba40a449fa1bcfb7 (includes draft-27 PSK cases).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decode, encode, Tag } from 'cbor2';
import { decrypt } from '../src/index.ts';
const vectors = JSON.parse(readFileSync(new URL('./fixtures/pr155.json', import.meta.url), 'utf8'));
const bytes = (s: string) => new TextEncoder().encode(s);
const psk = Uint8Array.from(Buffer.from('0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82', 'hex'));
function privateKey(hex: string) {
  const k = decode(Buffer.from(hex, 'hex')) as Map<number, any>;
  const b64 = (v: Uint8Array) => Buffer.from(v).toString('base64url');
  return { kty: k.get(1) === 2 ? 'EC' : 'OKP', crv: ({1:'P-256',2:'P-384',3:'P-521',4:'X25519',5:'X448'} as Record<number,string>)[k.get(-1)], x:b64(k.get(-2)), ...(k.has(-3) ? {y:b64(k.get(-3))} : {}), d:b64(k.get(-4)) };
}
for (const v of vectors) {
 test(v.name, async () => {
  const options = {
   externalAad: v.name.includes('external aad') ? bytes('external-aad') : undefined,
   externalInfo: v.name.includes('external info') ? bytes('external-info') : undefined,
   recipientExtraInfo: v.name.includes('external info') ? bytes('external-info') : undefined,
   hpkeAad: v.name.includes('external hpke aad') ? bytes('external-hpke-aad') : undefined,
   psk: v.name.includes('PSK') ? psk : undefined,
  };
  const ciphertext = Uint8Array.from(Buffer.from(v.ciphertext, 'hex'));
  const body = (decode(ciphertext) as Tag).contents as any[];
  if (v.name.includes('-KE')) assert.equal(body[1].get(5).length, 12);
  assert.equal(new TextDecoder().decode(await decrypt(ciphertext, privateKey(v.key), options)), 'hpke test payload');
  if (v.name.includes('PSK')) {
   await assert.rejects(() => decrypt(ciphertext, privateKey(v.key), {...options, psk: undefined}));
   await assert.rejects(() => decrypt(ciphertext, privateKey(v.key), {...options, psk: new Uint8Array(32)}));
  }
 });
}

test('rejects non-96-bit IVs from the pre-PR155 vectors', async () => {
 const v = vectors.find((v: any) => v.name.startsWith('HPKE-7-KE with default aad, default info, default hpke aad'));
 for (const length of [0, 8, 16, 32]) {
  const tagged = decode(Uint8Array.from(Buffer.from(v.ciphertext, 'hex'))) as Tag;
  (tagged.contents as any[])[1].set(5, new Uint8Array(length));
  await assert.rejects(() => decrypt(encode(tagged), privateKey(v.key)), /IV must be 12 bytes/);
 }
});
test('rejects unprotected psk_id', async () => {
 const v = vectors.find((v: any) => v.name.startsWith('HPKE-7 Encrypt0 with default aad and default info'));
 const tagged = decode(Uint8Array.from(Buffer.from(v.ciphertext, 'hex'))) as Tag;
 (tagged.contents as any[])[1].set(-5, bytes('unprotected'));
 await assert.rejects(() => decrypt(encode(tagged), privateKey(v.key)), /psk_id must be protected/);
});

import { encrypt, generateKeyPair } from '../src/index.ts';
import { contentEncrypt } from '../src/contentEncryption.ts';
test('PSK round trips through the public API in both modes', async () => {
 const {publicKeyJwk, privateKeyJwk} = await generateKeyPair();
 for (const mode of ['integrated', 'keyEncryption'] as const) {
  const options = {mode, psk, pskId: bytes('roundtrip'), externalInfo: bytes('info'), recipientExtraInfo: bytes('info'), hpkeAad: bytes('wrap-aad')};
  const ct = await encrypt(bytes('roundtrip'), publicKeyJwk, options);
  assert.equal(new TextDecoder().decode(await decrypt(ct, privateKeyJwk, options)), 'roundtrip');
 }
});
test('rejects invalid AES-GCM IVs on encryption for all AES key sizes', async () => {
 for (const [alg, keySize] of [[1,16],[2,24],[3,32]] as const) {
  await assert.rejects(() => contentEncrypt(alg, new Uint8Array(keySize), new Uint8Array(keySize), bytes('test'), new Uint8Array()), /IV must be 12 bytes/);
 }
});

test('rejects wrong-mode and unknown integrated algorithms', async () => {
 const v = vectors.find((v: any) => v.name.startsWith('HPKE-7 Encrypt0 with default aad and default info'));
 for (const alg of [53, -1, 999]) {
  const tagged = decode(Uint8Array.from(Buffer.from(v.ciphertext, 'hex'))) as Tag;
  const body = tagged.contents as any[];
  body[0] = encode(new Map([[1, alg]]));
  await assert.rejects(() => decrypt(encode(tagged), privateKey(v.key)), /[Ii]ntegrated/);
 }
});

test("PR155 corrected Section 5.2 example decrypts", async () => {
 const key = privateKey("a701020243626f6203182e2001215820d832916778598ea6203af974c97b45970ac0266fc6a3b7f213ba9f8b591b92972258208d9410599a8e83d00eb46d67b34d4dac8fbd4b8b1f08864599659cee9ef09184235820b1162c568efcba91c8e4e82f66e36b45aa10bc55228cf65ecd3bb29cfb09f989");
 const ct = Uint8Array.from(Buffer.from("d8608443a10101a1054c8623f0b68ccc19415e37b8db5824ded3a96e205d71b031d01e20186b0c43cde13d701d8f388358bf9504d06238f805c6aa10818349a201182e0443626f62a123584104d0982992abbc8bafd26840dd46b2e976e0d36542625041ae315acd52cd704a88e90ec1b1ecf05fcf2355b1289e87315ddb0cbb85d3c3deb01d6a47e76f3279a8582095e40717a9e15dfd863ec4725e4dfb4648b5627d125f946e0e2f4c9b9e27989d", "hex"));
 assert.equal(new TextDecoder().decode(await decrypt(ct, key)), "This is the content.");
});
