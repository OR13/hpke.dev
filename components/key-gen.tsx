"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import pako from "pako";
import { base64url } from "jose";
import { generateKeyPair, publicFromPrivate, type Jwk } from "@hpke-jose";
import {
  ArrowRightIcon,
  DiceFiveIcon,
  DownloadSimpleIcon,
  KeyIcon,
} from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FileDrop } from "@/components/file-drop";

function downloadJson(obj: unknown, name: string) {
  const href =
    "data:text/json;charset=utf-8," +
    encodeURIComponent(JSON.stringify(obj, null, 2));
  const a = document.createElement("a");
  a.setAttribute("href", href);
  a.setAttribute("download", `${name}.json`);
  document.body.appendChild(a);
  a.click();
  a.remove();
}

const keyName = (k: Jwk) => {
  const kind = k.d ? "private" : "public";
  const id = (k.kid ?? "").split(":").pop()?.slice(0, 16) ?? "key";
  return `${kind}.${id}`;
};

function encryptToPublicKey(router: ReturnType<typeof useRouter>, pub: Jwk) {
  const compressed = pako.gzip(new TextEncoder().encode(JSON.stringify(pub)));
  router.push(`/encrypt#pako:${base64url.encode(compressed)}`);
}

export function KeyGen() {
  const router = useRouter();
  const [privateKey, setPrivateKey] = React.useState<Jwk>();

  const generate = React.useCallback(async () => {
    const { privateKeyJwk } = await generateKeyPair("HPKE-0");
    setPrivateKey(privateKeyJwk);
  }, []);

  React.useEffect(() => {
    void generate();
  }, [generate]);

  const publicKey = privateKey ? publicFromPrivate(privateKey) : undefined;

  const onDropPublicKey = async (files: File[]) => {
    try {
      const jwk = JSON.parse(await files[0].text()) as Jwk;
      encryptToPublicKey(router, jwk);
    } catch {
      toast.error("That doesn't look like a public key JWK.");
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <KeyIcon className="size-5" weight="fill" /> Recipient key
            </CardTitle>
            <CardDescription>
              Generate an HPKE-0 (P-256) key pair. Keep the private key; share the public key.
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={generate}>
            <DiceFiveIcon className="size-4" weight="bold" /> New key
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <pre className="max-h-72 overflow-auto rounded-lg border border-border bg-muted/40 p-4 text-xs leading-relaxed">
          {publicKey ? JSON.stringify(publicKey, null, 2) : "Generating…"}
        </pre>

        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            size="sm"
            disabled={!privateKey}
            onClick={() => privateKey && downloadJson(privateKey, keyName(privateKey))}
          >
            <DownloadSimpleIcon className="size-4" weight="bold" /> Export private key
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={!publicKey}
            onClick={() => publicKey && downloadJson(publicKey, keyName(publicKey))}
          >
            <DownloadSimpleIcon className="size-4" weight="bold" /> Export public key
          </Button>
          <Button
            size="sm"
            disabled={!publicKey}
            onClick={() => publicKey && encryptToPublicKey(router, publicKey)}
          >
            Encrypt to this key <ArrowRightIcon className="size-4" weight="bold" />
          </Button>
        </div>

        <FileDrop
          dragText="Drag an exported public key here to encrypt to it"
          dropText="Drop to encrypt to this key."
          onFilesAccepted={onDropPublicKey}
        />
      </CardContent>
    </Card>
  );
}
