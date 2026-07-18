"use client";

import * as React from "react";
import Link from "next/link";
import Pako from "pako";
import { base64url } from "jose";
import type { Jwk } from "@hpke-jose";

import { SiteHeader } from "@/components/site-header";
import { SiteFooter } from "@/components/site-footer";
import { EncryptPanel } from "@/components/encrypt-panel";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

export default function EncryptPage() {
  const [publicKeyJwk, setPublicKeyJwk] = React.useState<Jwk>();

  React.useEffect(() => {
    if (window.location.hash.startsWith("#pako:")) {
      const encoded = window.location.hash.replace("#pako:", "");
      const jwk = JSON.parse(
        new TextDecoder().decode(Pako.inflate(base64url.decode(encoded))),
      ) as Jwk;
      setPublicKeyJwk(jwk);
    }
  }, []);

  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />
      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-10">
        <h1 className="mb-6 font-heading text-2xl font-bold tracking-tight">Encrypt</h1>
        {publicKeyJwk ? (
          <EncryptPanel publicKeyJwk={publicKeyJwk} />
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>No recipient key</CardTitle>
              <CardDescription>
                Generate or load a recipient key, then choose “Encrypt to this key”.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Link href="/#demo" className={cn(buttonVariants())}>
                Go to key generation
              </Link>
            </CardContent>
          </Card>
        )}
      </main>
      <SiteFooter />
    </div>
  );
}
