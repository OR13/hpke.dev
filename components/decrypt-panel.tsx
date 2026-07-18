"use client";

import * as React from "react";
import { toast } from "sonner";
import {
  decrypt as hpkeDecrypt,
  jweMode,
  type HpkeJwe,
  type Jwk,
} from "@hpke-jose";
import { decrypt as coseDecrypt, readAlg, SUITE_PARAMS } from "@cose-hpke";
import {
  decodeHpkeJweFragment,
  decodeHpkeCoseFragment,
  isHpkeCoseFragment,
} from "@/services/hpke-url";
import { TEST_KEYS } from "@/services/test-keys";
import { LockKeyOpenIcon, CopyIcon, FlaskIcon } from "@phosphor-icons/react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FileDrop } from "@/components/file-drop";

export function DecryptPanel({ fragment }: { fragment: string }) {
  const [message, setMessage] = React.useState<string>();
  const isCose = isHpkeCoseFragment(fragment);

  const format = React.useMemo(() => {
    try {
      if (isCose) {
        const alg = readAlg(decodeHpkeCoseFragment(fragment));
        const label = alg ? SUITE_PARAMS[alg]?.label : undefined;
        return `COSE HPKE · Encrypt0${label ? ` · ${label}` : ""}`;
      }
      return `JOSE HPKE · ${jweMode(decodeHpkeJweFragment(fragment) as HpkeJwe)}`;
    } catch {
      return isCose ? "COSE HPKE" : "JOSE HPKE";
    }
  }, [fragment, isCose]);

  const raw = fragment;

  const decryptWith = async (privateKey: Jwk) => {
    try {
      const plaintext = isCose
        ? await coseDecrypt(decodeHpkeCoseFragment(fragment), privateKey)
        : await hpkeDecrypt(decodeHpkeJweFragment(fragment), privateKey);
      setMessage(new TextDecoder().decode(plaintext));
    } catch {
      toast.error("Decryption failed.", {
        description: "Wrong key, or the message is malformed.",
      });
    }
  };

  const onDropPrivateKey = async (files: File[]) => {
    try {
      await decryptWith(JSON.parse(await files[0].text()) as Jwk);
    } catch {
      toast.error("That doesn't look like a private key JWK.");
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <LockKeyOpenIcon className="size-5" weight="fill" /> Encrypted message
            </CardTitle>
            <CardDescription>Drop the recipient private key to decrypt.</CardDescription>
          </div>
          {format ? <Badge variant="outline">{format}</Badge> : null}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <button
          type="button"
          onClick={() => {
            navigator.clipboard.writeText(raw);
            toast.success("Copied encrypted payload to clipboard.");
          }}
          className="flex w-full items-center gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2 text-left text-xs text-muted-foreground transition-colors hover:bg-muted"
        >
          <CopyIcon className="size-4 shrink-0" weight="bold" />
          <span className="truncate font-mono">{raw.slice(0, 96)}…</span>
        </button>

        {message !== undefined ? (
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
              <LockKeyOpenIcon className="size-4" weight="fill" /> Decrypted
            </div>
            <pre className="overflow-auto whitespace-pre-wrap text-sm leading-relaxed">
              {message}
            </pre>
          </div>
        ) : (
          <div className="space-y-3">
            <FileDrop
              dragText="Drag the exported private key here"
              dropText="Drop to decrypt."
              onFilesAccepted={onDropPrivateKey}
            />
            {TEST_KEYS.length > 0 ? (
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  Or decrypt with a built-in test key:
                </span>
                {TEST_KEYS.map((k) => (
                  <Button
                    key={k.name}
                    variant="secondary"
                    size="sm"
                    onClick={() => decryptWith(k.privateKeyJwk)}
                  >
                    <FlaskIcon className="size-4" weight="bold" /> {k.name}
                  </Button>
                ))}
              </div>
            ) : null}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
