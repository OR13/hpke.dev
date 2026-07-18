# hpke.dev

Interoperability testing for JOSE and COSE based HPKE Envelopes.

Work in progress...

## JOSE HPKE

The JOSE path implements
[draft-ietf-jose-hpke-encrypt-22](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/)
(HPKE Integrated Encryption, `HPKE-0` / P-256) in
[`packages/hpke-jose`](./packages/hpke-jose), built on
[`panva/hpke`](https://github.com/panva/hpke). Run its tests with `bun test`
from that directory.

## Sharing messages by URL

An encrypted message is shared entirely inside the URL **fragment**, so the
ciphertext never reaches the server:

```
https://hpke.dev/decrypt#gzip:base64url:hpke:jwe:<base64url(gzip(json JWE))>
```

The sender encrypts to a recipient's public JWK, gzips the JSON-serialized JWE,
base64url-encodes it, and prepends the `gzip:base64url:hpke:jwe:` scheme tag. The
recipient opens the link and drops in their private key to decrypt. See
[`services/hpke-url.ts`](./services/hpke-url.ts).


## Goals

- Single Recipient COSE HPKE.
- Multiple Recipient JOSE HPKE.
- Multiple Recipient COSE HPKE.

- Scan a QR Code to Encrypt to a Public Key
- Scan a QR Code to Decrypt a Message

