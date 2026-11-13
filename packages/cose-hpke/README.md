# @hpke.dev/cose-hpke

A fresh, first-party implementation of
[draft-ietf-cose-hpke-27](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)
(HPKE for COSE), built on [`panva/hpke`](https://github.com/panva/hpke) and
[`cbor2`](https://github.com/hildjj/cbor2). Runs anywhere Web Crypto is available
— Bun, Node, Deno, and the browser — and is fully under this repo's control
(replacing the previous `@transmute/cose` dependency).

## What's implemented

Both COSE HPKE modes, single recipient:

### Integrated Encryption (`HPKE-0` … `HPKE-7`) — tagged `COSE_Encrypt0`

```
16([ protected{1: alg}, unprotected{-4: ek}, ciphertext ])
```

- `ek` (encapsulated key) in the unprotected header; ciphertext is the HPKE `Seal`
  output
- HPKE `aad` = CBOR `Enc_structure` `["Encrypt0", protected, external_aad]`
  (RFC 9052 §5.3); HPKE `info` empty

### Key Encryption (`HPKE-0-KE` … `HPKE-7-KE`) — tagged `COSE_Encrypt`

```
96([ protected{1: enc}, unprotected{5: iv}, ciphertext,
     [ [ protected{1: alg}, unprotected{-4: ek}, encrypted_key ] ] ])
```

- HPKE wraps a random CEK (`encrypted_key`); the content is encrypted with the CEK
  using a COSE AES-GCM or ChaCha20-Poly1305 `enc`
- HPKE `aad` empty; HPKE `info` = CBOR `Recipient_structure`
  `["HPKE Recipient", enc, recipient_protected, extra]` (Section 3.3.1)

The draft-27 tables (`HPKE-0`=35 … `HPKE-7`=45; `HPKE-0-KE`=46 … `HPKE-7-KE`=53)
live in [`src/suites.ts`](./src/suites.ts). `HPKE-0` (P-256 / HKDF-SHA256 /
AES-128-GCM) is the demo default and shares its ciphersuite with JOSE `HPKE-0`, so
the same P-256 JWK works everywhere.

## Usage

```ts
import { generateKeyPair, encrypt, decrypt, publicFromPrivate } from "@hpke.dev/cose-hpke";

const { privateKeyJwk } = await generateKeyPair();       // HPKE-0 (P-256)
const publicKeyJwk = publicFromPrivate(privateKeyJwk);

// Integrated (default) or Key Encryption
const cose = await encrypt(new TextEncoder().encode("hello"), publicKeyJwk);
const coseKE = await encrypt(new TextEncoder().encode("hello"), publicKeyJwk, {
  mode: "keyEncryption",
});

// decrypt() auto-detects the mode from the CBOR tag (16 vs 96).
new TextDecoder().decode(await decrypt(cose, privateKeyJwk));   // "hello"
new TextDecoder().decode(await decrypt(coseKE, privateKeyJwk)); // "hello"
```

## Tests

```sh
bun run test
```

## Draft-27 and PR #155 interoperability

Supports base and PSK modes. Supply `psk` (at least 32 bytes) and `pskId`
(nonempty bytes) on encryption. Decryption reads the protected `psk_id` (-5)
and requires the external `psk`; an optional `pskId` must match. PSK material
is never serialized. Unprotected `psk_id` is rejected.

`externalInfo` supplies integrated HPKE info; `recipientExtraInfo` supplies
Key Encryption context; `hpkeAad` supplies optional CEK wrap/unwrap AAD
(default empty, as recommended by the draft). `externalAad` binds layer 0.
Content algorithms: A128GCM (1), A192GCM (2), A256GCM (3), ChaCha20/Poly1305 (24).
All use 12-byte nonces; other lengths are rejected.

The Node vector suite decrypts all 192 upstream vectors from
[PR #155](https://github.com/cose-wg/draft-ietf-cose-hpke/pull/155), pinned to
`8cef948f1d8173ec4a21da61ba40a449fa1bcfb7`, including all suites, external
inputs, and PSK cases. Node is used for Web Crypto X448/ChaCha20 support.
The PR fixes invalid AES-GCM IVs in earlier examples; both old and new
implementations generate 12-byte IVs, and this version rejects invalid IVs.
Algorithm/header labels remain the draft's assumed assignments.
