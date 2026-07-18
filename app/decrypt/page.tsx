"use client";

import * as React from "react";
import Link from "next/link";

import { SiteHeader } from "@/components/site-header";
import { SiteFooter } from "@/components/site-footer";
import { DecryptPanel } from "@/components/decrypt-panel";
import { isHpkeJweFragment, isHpkeCoseFragment } from "@/services/hpke-url";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

export default function DecryptPage() {
  const [fragment, setFragment] = React.useState<string>();

  React.useEffect(() => {
    const hash = window.location.hash;
    if (isHpkeJweFragment(hash) || isHpkeCoseFragment(hash)) {
      setFragment(hash);
    }
  }, []);

  const hasMessage = Boolean(fragment);

  return (
    <div className="flex min-h-dvh flex-col">
      <SiteHeader />
      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-10">
        <h1 className="mb-6 font-heading text-2xl font-bold tracking-tight">Decrypt</h1>
        {hasMessage && fragment ? (
          <DecryptPanel fragment={fragment} />
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>No message</CardTitle>
              <CardDescription>
                Open a shared HPKE link (its ciphertext lives in the URL fragment), or create
                one on the encrypt page.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Link
                href="/#demo"
                className={cn(buttonVariants({ variant: "outline" }))}
              >
                Create a message
              </Link>
            </CardContent>
          </Card>
        )}
      </main>
      <SiteFooter />
    </div>
  );
}
