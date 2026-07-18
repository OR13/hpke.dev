# Test keys

Throwaway HPKE-0 (P-256) key pairs for exercising the demo. **Not secret** — they
are committed on purpose so shared test links are reproducible. Never use them for
anything real.

- `alice.private.json` — drop this into the [decrypt page](https://hpke.dev/decrypt)
  to open links encrypted to `alice`.
- `alice.public.json` — encrypt to this with the CLI.

## Make a shareable test link

```sh
bun run cli/hpke.ts encrypt \
  --to test-keys/alice.public.json \
  --message "hello" \
  --mode integrated        # or: keyEncryption

# → prints  https://hpke.dev/decrypt#gzip:base64url:hpke:jwe:…
```

Open the printed link, then drop `test-keys/alice.private.json` into the page to
decrypt. Verify from the CLI without a browser:

```sh
bun run cli/hpke.ts decrypt --key test-keys/alice.private.json --url "<link>"
```

Generate a fresh pair with `bun run cli/hpke.ts keygen --name bob`.
