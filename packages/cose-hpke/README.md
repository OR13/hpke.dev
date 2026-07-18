# @hpke.dev/cose-hpke

A fresh, first-party implementation of
[draft-ietf-cose-hpke-26](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)
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
  using a COSE AES-GCM `enc`
- HPKE `aad` empty; HPKE `info` = CBOR `Recipient_structure`
  `["HPKE Recipient", enc, recipient_protected, extra]` (Section 3.3.1)

The draft-26 tables (`HPKE-0`=35 … `HPKE-7`=45; `HPKE-0-KE`=46 … `HPKE-7-KE`=53)
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
bun test
```
