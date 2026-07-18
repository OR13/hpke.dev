import Link from "next/link";
import {
  ArrowRightIcon,
  StackIcon,
  LinkSimpleIcon,
  BracketsCurlyIcon,
  AtomIcon,
  GlobeHemisphereWestIcon,
  PackageIcon,
  ShieldCheckIcon,
} from "@phosphor-icons/react/dist/ssr";

import { SiteHeader } from "@/components/site-header";
import { SiteFooter } from "@/components/site-footer";
import { KeyGen } from "@/components/key-gen";
import { buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const FEATURES = [
  {
    icon: StackIcon,
    title: "Two draft-22 formats",
    body: "Integrated Encryption and Key Encryption (the -KE algorithms), auto-detected on decrypt.",
  },
  {
    icon: LinkSimpleIcon,
    title: "Shareable links",
    body: "The ciphertext lives in the URL fragment (#gzip:base64url:hpke:jwe:…) — it never reaches a server.",
  },
  {
    icon: BracketsCurlyIcon,
    title: "JOSE & COSE",
    body: "Encrypt to JSON (JWE) or CBOR (COSE_Encrypt0) envelopes from the same public key.",
  },
  {
    icon: AtomIcon,
    title: "Post-quantum ready",
    body: "HPKE brings KEMs — including ML-KEM hybrids — within reach of JWE.",
  },
  {
    icon: GlobeHemisphereWestIcon,
    title: "Runs on Web Crypto",
    body: "Browser, Node, Deno, and Bun — no native bindings, no server round-trip.",
  },
  {
    icon: PackageIcon,
    title: "Built on panva/hpke",
    body: "A fresh, tested implementation on top of panva/hpke and panva/jose.",
  },
];

const STEPS = [
  {
    n: "01",
    title: "Generate a key",
    body: "Create an HPKE-0 (P-256) key pair in your browser. Keep the private key; share the public one.",
  },
  {
    n: "02",
    title: "Encrypt a message",
    body: "Compose text and seal it to the public key — pick Integrated or Key Encryption, JOSE or COSE.",
  },
  {
    n: "03",
    title: "Share the link",
    body: "You get a /decrypt#… link. The recipient opens it and drops in their private key to read it.",
  },
];

export default function Home() {
  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />
      <main className="flex-1">
        {/* Hero */}
        <section className="border-b border-border">
          <div className="mx-auto max-w-5xl px-4 py-20 sm:py-28">
            <Badge variant="outline" className="mb-6 gap-1.5">
              <ShieldCheckIcon className="size-3.5" weight="fill" />
              draft-ietf-jose-hpke-encrypt-22
            </Badge>
            <h1 className="max-w-3xl font-heading text-4xl font-bold leading-[1.1] tracking-tight sm:text-6xl">
              Encrypt a message to a public key, share it as a link.
            </h1>
            <p className="mt-6 max-w-2xl text-lg text-muted-foreground">
              HPKE.dev is an interactive playground for Hybrid Public Key Encryption with JOSE and
              COSE. Everything runs in your browser — the ciphertext travels in the URL fragment.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link href="#demo" className={cn(buttonVariants({ size: "lg" }))}>
                Try the demo <ArrowRightIcon className="size-4" weight="bold" />
              </Link>
              <a
                href="https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/"
                target="_blank"
                rel="noreferrer"
                className={cn(buttonVariants({ size: "lg", variant: "outline" }))}
              >
                Read the draft
              </a>
            </div>
            <pre className="mt-12 overflow-x-auto rounded-lg border border-border bg-muted/40 p-4 text-xs text-muted-foreground sm:text-sm">
              https://hpke.dev/decrypt#gzip:base64url:hpke:jwe:<span className="text-foreground">eNqNk1tv…</span>
            </pre>
          </div>
        </section>

        {/* Features */}
        <section className="border-b border-border">
          <div className="mx-auto max-w-5xl px-4 py-16">
            <h2 className="font-heading text-2xl font-bold tracking-tight">What it does</h2>
            <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {FEATURES.map((f) => (
                <Card key={f.title}>
                  <CardContent className="space-y-3 py-6">
                    <f.icon className="size-6" weight="duotone" />
                    <h3 className="font-heading font-semibold">{f.title}</h3>
                    <p className="text-sm text-muted-foreground">{f.body}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* How it works */}
        <section className="border-b border-border">
          <div className="mx-auto max-w-5xl px-4 py-16">
            <h2 className="font-heading text-2xl font-bold tracking-tight">How it works</h2>
            <div className="mt-8 grid gap-6 sm:grid-cols-3">
              {STEPS.map((s) => (
                <div key={s.n} className="space-y-2">
                  <div className="font-heading text-3xl font-bold text-muted-foreground/40">
                    {s.n}
                  </div>
                  <h3 className="font-heading font-semibold">{s.title}</h3>
                  <p className="text-sm text-muted-foreground">{s.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Demo */}
        <section id="demo" className="scroll-mt-16">
          <div className="mx-auto max-w-3xl px-4 py-16">
            <h2 className="font-heading text-2xl font-bold tracking-tight">Try it</h2>
            <p className="mb-8 mt-2 text-sm text-muted-foreground">
              Generate a key, then encrypt a message to it and share the link.
            </p>
            <KeyGen />
          </div>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
