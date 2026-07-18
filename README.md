# hpke.dev

Interoperability testing for JOSE and COSE based HPKE Envelopes.

An interactive playground: encrypt a message to a public key and share it as a
link. Built with **Next.js 16 (App Router, Turbopack) · React 19 · Tailwind v4 ·
shadcn/ui (base-lyra)**.

## JOSE HPKE

The JOSE path implements
[draft-ietf-jose-hpke-encrypt-22](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/)
in [`packages/hpke-jose`](./packages/hpke-jose), built on
[`panva/hpke`](https://github.com/panva/hpke) and [`panva/jose`](https://github.com/panva/jose).
Both draft formats are supported — **Integrated Encryption** (`HPKE-0`…`HPKE-7`)
and **Key Encryption** (`HPKE-0-KE`…`HPKE-7-KE`) — and `decrypt()` auto-detects
which. Run the tests with `bun test` from that directory.

## COSE HPKE

The COSE path implements
[draft-ietf-cose-hpke-26](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)
(HPKE `COSE_Encrypt0`, Integrated Encryption) in
[`packages/cose-hpke`](./packages/cose-hpke), built on `panva/hpke` and
[`cbor2`](https://github.com/hildjj/cbor2) — a first-party replacement for the
previous `@transmute/cose` dependency. COSE messages are shared with the parallel
`#gzip:base64url:hpke:cose:<…>` URL fragment scheme.

## CLI

A small [`cli/hpke.ts`](./cli/hpke.ts) (run with Bun) generates clickable test
links against the live site:

```sh
# encrypt to a committed test key and print a shareable link
bun run cli/hpke.ts encrypt --to test-keys/alice.public.json -m "hello" --mode integrated
# → https://hpke.dev/decrypt#gzip:base64url:hpke:jwe:…
# --mode keyEncryption (JOSE -KE) or --mode cose (COSE_Encrypt0) also work

# verify it round-trips, no browser needed
bun run cli/hpke.ts decrypt --key test-keys/alice.private.json --url "<link>"
```

See [`test-keys/`](./test-keys) for the throwaway keys.

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

