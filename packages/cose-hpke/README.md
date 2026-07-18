# @hpke.dev/cose-hpke

A fresh, first-party implementation of
[draft-ietf-cose-hpke-26](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)
(HPKE for COSE), built on [`panva/hpke`](https://github.com/panva/hpke) and
[`cbor2`](https://github.com/hildjj/cbor2). Runs anywhere Web Crypto is available
— Bun, Node, Deno, and the browser — and is fully under this repo's control
(replacing the previous `@transmute/cose` dependency).

## What's implemented

**COSE HPKE Integrated Encryption**, single recipient, as a tagged
`COSE_Encrypt0`:

```
16([ protected, unprotected, ciphertext ])
```

- protected header carries the HPKE algorithm (`1: alg`, e.g. `HPKE-0` = `35`)
- unprotected header carries the HPKE encapsulated key (`-4: ek`, a byte string)
- ciphertext is the HPKE `Seal` output
- HPKE `aad` = the CBOR `Enc_structure` `["Encrypt0", protected, external_aad]`
  (RFC 9052 §5.3); HPKE `info` is empty

The draft-26 algorithm table (`HPKE-0`=35 … `HPKE-7`=45) lives in
[`src/suites.ts`](./src/suites.ts). `HPKE-0` (P-256 / HKDF-SHA256 / AES-128-GCM)
is the demo default and shares its ciphersuite with JOSE `HPKE-0`, so the same
P-256 JWK works for both.

## Usage

```ts
import { generateKeyPair, encrypt, decrypt, publicFromPrivate } from "@hpke.dev/cose-hpke";

const { privateKeyJwk } = await generateKeyPair();       // HPKE-0 (P-256)
const publicKeyJwk = publicFromPrivate(privateKeyJwk);

const cose = await encrypt(new TextEncoder().encode("hello"), publicKeyJwk);
// -> tagged COSE_Encrypt0 bytes (Uint8Array)

new TextDecoder().decode(await decrypt(cose, privateKeyJwk)); // "hello"
```

## Tests

```sh
bun test
```
