import type { Metadata } from "next";
import { ArrowSquareOutIcon, LinkSimpleIcon } from "@phosphor-icons/react/dist/ssr";

import { SiteHeader } from "@/components/site-header";
import { SiteFooter } from "@/components/site-footer";
import { Card, CardContent } from "@/components/ui/card";

export const metadata: Metadata = { title: "About" };

const resources = [
  {
    primary: "hpke.dev",
    secondary: "HPKE interoperability for JOSE and COSE.",
    link: "https://github.com/OR13/hpke.dev",
  },
  {
    primary: "Use of HPKE with JOSE",
    secondary: "draft-ietf-jose-hpke-encrypt — the format this demo implements.",
    link: "https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/",
  },
  {
    primary: "Use of HPKE with COSE",
    secondary: "draft-ietf-cose-hpke",
    link: "https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/",
  },
  {
    primary: "Hybrid Public Key Encryption",
    secondary: "RFC 9180",
    link: "https://www.rfc-editor.org/rfc/rfc9180.html",
  },
  {
    primary: "panva/hpke",
    secondary:
      "Hybrid Public Key Encryption for Node.js, Browser, Deno, Bun, and other Web-interoperable runtimes.",
    link: "https://github.com/panva/hpke",
  },
  {
    primary: "panva/jose",
    secondary: "JWA, JWS, JWE, JWT, JWK, JWKS for Web-interoperable runtimes.",
    link: "https://github.com/panva/jose",
  },
  {
    primary: "cbor2",
    secondary: "Modern, web-first CBOR for JavaScript — powers the in-repo COSE HPKE implementation.",
    link: "https://github.com/hildjj/cbor2",
  },
];

export default function AboutPage() {
  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />
      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-10">
        <h1 className="mb-2 font-heading text-2xl font-bold tracking-tight">Resources</h1>
        <p className="mb-8 text-sm text-muted-foreground">
          Specifications and libraries behind this playground.
        </p>
        <div className="space-y-3">
          {resources.map((r) => (
            <a key={r.link} href={r.link} target="_blank" rel="noreferrer" className="block">
              <Card className="transition-colors hover:border-foreground/30 hover:bg-muted/40">
                <CardContent className="flex items-center gap-4 py-4">
                  <LinkSimpleIcon className="size-5 shrink-0 text-muted-foreground" weight="bold" />
                  <div className="min-w-0 flex-1">
                    <div className="font-heading font-medium">{r.primary}</div>
                    <div className="text-sm text-muted-foreground">{r.secondary}</div>
                  </div>
                  <ArrowSquareOutIcon className="size-4 shrink-0 text-muted-foreground" weight="bold" />
                </CardContent>
              </Card>
            </a>
          ))}
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}
