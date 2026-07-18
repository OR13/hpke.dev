#!/usr/bin/env bun
/**
 * hpke.dev test CLI
 *
 * Generate keys, encrypt a message to a public key and print a clickable
 * https://hpke.dev/decrypt#… link, or decrypt such a link with a private key.
 *
 * Usage:
 *   bun run cli/hpke.ts keygen  --name bob [--alg HPKE-0] [--out test-keys]
 *   bun run cli/hpke.ts encrypt --to <public.json> --message "hi"
 *                               [--mode integrated|keyEncryption] [--enc A128GCM]
 *                               [--base https://hpke.dev]
 *   bun run cli/hpke.ts decrypt --key <private.json> --url "<url-or-fragment>"
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  generateKeyPair,
  publicFromPrivate,
  encrypt,
  decrypt,
  jweMode,
  type HpkeMode,
  type IntegratedAlg,
  type Jwk,
} from "@hpke-jose";
import { encodeHpkeJweFragment, decodeHpkeJweFragment } from "../services/hpke-url";

const DEFAULT_BASE = "https://hpke.dev";

function parseArgs(argv: string[]) {
  const [command, ...rest] = argv;
  const flags: Record<string, string> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next === undefined || next.startsWith("--")) flags[key] = "true";
      else {
        flags[key] = next;
        i++;
      }
    } else if (a === "-m") {
      flags.message = rest[++i];
    }
  }
  return { command, flags };
}

async function readJwk(path: string): Promise<Jwk> {
  return JSON.parse(await readFile(path, "utf8")) as Jwk;
}

async function keygen(flags: Record<string, string>) {
  const alg = (flags.alg ?? "HPKE-0") as IntegratedAlg;
  const name = flags.name ?? "key";
  const out = flags.out ?? "test-keys";
  const { privateKeyJwk } = await generateKeyPair(alg);
  const publicKeyJwk = publicFromPrivate(privateKeyJwk);
  await mkdir(out, { recursive: true });
  const priv = join(out, `${name}.private.json`);
  const pub = join(out, `${name}.public.json`);
  await writeFile(priv, JSON.stringify(privateKeyJwk, null, 2) + "\n");
  await writeFile(pub, JSON.stringify(publicKeyJwk, null, 2) + "\n");
  console.log(`Generated ${alg} key pair (${publicKeyJwk.kid})`);
  console.log(`  private: ${priv}`);
  console.log(`  public:  ${pub}`);
}

async function readMessage(flags: Record<string, string>): Promise<string> {
  if (flags.message && flags.message !== "-") return flags.message;
  if (flags.file) return readFile(flags.file, "utf8");
  // read stdin
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Uint8Array);
  return Buffer.concat(chunks).toString("utf8");
}

async function encryptCmd(flags: Record<string, string>) {
  if (!flags.to) throw new Error("encrypt requires --to <public-key.json>");
  const publicKeyJwk = await readJwk(flags.to);
  const message = await readMessage(flags);
  const mode = (flags.mode ?? "integrated") as HpkeMode;
  const base = (flags.base ?? DEFAULT_BASE).replace(/\/$/, "");

  const jwe = await encrypt(new TextEncoder().encode(message), publicKeyJwk, {
    mode,
    enc: flags.enc as never,
    protectedHeader: publicKeyJwk.kid ? { kid: publicKeyJwk.kid } : undefined,
  });
  const url = `${base}/decrypt#${encodeHpkeJweFragment(jwe)}`;

  console.error(`mode:      ${jweMode(jwe)}`);
  console.error(`recipient: ${publicKeyJwk.kid ?? "(no kid)"}`);
  console.error(`url length: ${url.length}`);
  console.error("");
  console.log(url);
}

async function decryptCmd(flags: Record<string, string>) {
  if (!flags.key) throw new Error("decrypt requires --key <private-key.json>");
  if (!flags.url) throw new Error("decrypt requires --url <url-or-fragment>");
  const privateKeyJwk = await readJwk(flags.key);
  const fragment = flags.url.includes("#") ? "#" + flags.url.split("#")[1] : flags.url;
  const jwe = decodeHpkeJweFragment(fragment);
  const plaintext = await decrypt(jwe, privateKeyJwk);
  console.error(`mode: ${jweMode(jwe)}`);
  console.error("");
  process.stdout.write(new TextDecoder().decode(plaintext));
  if (!process.stdout.write("")) {
    /* flush */
  }
  console.log();
}

const HELP = `hpke.dev test CLI

Commands:
  keygen  --name <n> [--alg HPKE-0] [--out test-keys]
  encrypt --to <public.json> --message "<text>" [--mode integrated|keyEncryption]
          [--enc A128GCM|A192GCM|A256GCM] [--base https://hpke.dev]
  decrypt --key <private.json> --url "<url-or-fragment>"
`;

async function main() {
  const { command, flags } = parseArgs(process.argv.slice(2));
  switch (command) {
    case "keygen":
      return keygen(flags);
    case "encrypt":
      return encryptCmd(flags);
    case "decrypt":
      return decryptCmd(flags);
    default:
      console.log(HELP);
      if (command && command !== "help") process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
});
