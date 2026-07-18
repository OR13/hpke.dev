# @hpke.dev/jose-hpke

A fresh, from-scratch implementation of
[draft-ietf-jose-hpke-encrypt-22](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/)
(HPKE for JOSE), built on [`panva/hpke`](https://github.com/panva/hpke) and
[`jose`](https://github.com/panva/jose). Runs anywhere Web Crypto is available —
Bun, Node, Deno, and the browser.

This replaces the old `services/jose-hpke` copy, which tracked the long-obsolete
`draft-rha-jose-hpke-encrypt` wire format (`epk.ek` in the header).

## What's implemented

**Both** encryption formats the draft defines, JSON (and Compact, for Integrated):

### Integrated Encryption (`HPKE-0` .. `HPKE-7`)

- Protected header carries `alg` (an `HPKE-N` label) and MUST NOT carry `enc`.
- JWE Encrypted Key = HPKE **encapsulated secret**; ciphertext = HPKE `Seal`
  output (AEAD tag included).
- JWE Initialization Vector and Authentication Tag are **empty**.
- HPKE `aad` = `ASCII(Encoded Protected Header)` (or `…'.'BASE64URL(JWE AAD)`);
  HPKE `info` is empty.

### Key Encryption (`HPKE-0-KE` .. `HPKE-7-KE`)

- Protected header carries `alg` (an `HPKE-N-KE` label), `enc` (a standard JWE
  content-encryption algorithm — `A128GCM`/`A192GCM`/`A256GCM`), and `ek` (the
  base64url HPKE encapsulated secret).
- JWE Encrypted Key = HPKE `Seal` of a random CEK; the CEK then encrypts the
  plaintext with `enc`, producing non-empty `iv`/`ciphertext`/`tag`.
- HPKE `aad` is empty; HPKE `info` is the `Recipient_structure`
  `ASCII("JOSE-HPKE rcpt") || 0xFF || ASCII(enc) || 0xFF`.
- Content AEAD `aad` follows the same rule as Integrated.

The full draft-22 registry lives in [`src/suites.ts`](./src/suites.ts). The demo
defaults to **`HPKE-0`** / **`HPKE-0-KE`** (P-256) for the widest Web Crypto
support.

## Usage

```ts
import { generateKeyPair, encrypt, decrypt, publicFromPrivate } from "@hpke.dev/jose-hpke";

const { privateKeyJwk } = await generateKeyPair("HPKE-0");
const publicKeyJwk = publicFromPrivate(privateKeyJwk);

// Integrated Encryption (default)
const jwe = await encrypt(new TextEncoder().encode("hello"), publicKeyJwk);

// Key Encryption
const jweKE = await encrypt(new TextEncoder().encode("hello"), publicKeyJwk, {
  mode: "keyEncryption",
  enc: "A256GCM", // optional; defaults per the -KE algorithm
});

// decrypt() auto-detects the mode from the protected header `alg`.
new TextDecoder().decode(await decrypt(jwe, privateKeyJwk));   // "hello"
new TextDecoder().decode(await decrypt(jweKE, privateKeyJwk)); // "hello"
```

The mode-specific APIs are also exported directly as `integrated.{encrypt,decrypt}`
and `keyEncryption.{encrypt,decrypt}`.

Recipient keys are ordinary JWKs (`EC` for the NIST curves, `OKP` for
X25519/X448). Any P-256 EC JWK works even if its `alg` predates the draft-22
labels — the algorithm is resolved from the curve.

## Tests

```sh
bun test
```
