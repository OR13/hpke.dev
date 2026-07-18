# @hpke.dev/jose-hpke

A fresh, from-scratch implementation of
[draft-ietf-jose-hpke-encrypt-22](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/)
(HPKE for JOSE), built on [`panva/hpke`](https://github.com/panva/hpke) and
[`jose`](https://github.com/panva/jose). Runs anywhere Web Crypto is available —
Bun, Node, Deno, and the browser.

This replaces the old `services/jose-hpke` copy, which tracked the long-obsolete
`draft-rha-jose-hpke-encrypt` wire format (`epk.ek` in the header).

## What's implemented

**HPKE Integrated Encryption** (single recipient), JSON and Compact
serializations:

- The protected header carries `alg` (an `HPKE-N` label) and MUST NOT carry `enc`.
- The JWE Encrypted Key is the HPKE **encapsulated secret**.
- The ciphertext is the HPKE `Seal` output (AEAD tag included).
- The JWE Initialization Vector and Authentication Tag are **empty**.
- The HPKE `aad` is `ASCII(Encoded Protected Header)`, or
  `ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))` when a JWE AAD is
  present.
- The HPKE `info` is the empty octet sequence.

The full draft-22 algorithm registry (`HPKE-0`..`HPKE-7` and the `-KE` labels) is
declared in [`src/suites.ts`](./src/suites.ts). The demo defaults to **`HPKE-0`** —
`DHKEM(P-256, HKDF-SHA256)` + `HKDF-SHA256` + `AES-128-GCM` — for the widest
Web Crypto support. Key Encryption (`-KE`) assembly is registered but not yet
wired up.

## Usage

```ts
import { generateKeyPair, encrypt, decrypt, publicFromPrivate } from "@hpke.dev/jose-hpke";

const { privateKeyJwk } = await generateKeyPair("HPKE-0");
const publicKeyJwk = publicFromPrivate(privateKeyJwk);

const jwe = await encrypt(new TextEncoder().encode("hello"), publicKeyJwk);
// -> { protected, encrypted_key, ciphertext, iv: "", tag: "" }

const plaintext = await decrypt(jwe, privateKeyJwk);
new TextDecoder().decode(plaintext); // "hello"
```

Recipient keys are ordinary JWKs (`EC` for the NIST curves, `OKP` for
X25519/X448). Any P-256 EC JWK works even if its `alg` predates the draft-22
labels — the algorithm is resolved from the curve.

## Tests

```sh
bun test
```
