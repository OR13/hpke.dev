"use client";

import * as React from "react";
import { toast } from "sonner";
import {
  decrypt as hpkeDecrypt,
  jweMode,
  type HpkeJwe,
  type Jwk,
} from "@hpke-jose";
import { decodeHpkeJweFragment } from "@/services/hpke-url";
import { LockKeyOpenIcon, CopyIcon } from "@phosphor-icons/react";

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

export function DecryptPanel({ hpkeJweFragment }: { hpkeJweFragment: string }) {
  const [message, setMessage] = React.useState<string>();

  const format = React.useMemo(() => {
    try {
      return `JOSE HPKE · ${jweMode(decodeHpkeJweFragment(hpkeJweFragment) as HpkeJwe)}`;
    } catch {
      return "JOSE HPKE";
    }
  }, [hpkeJweFragment]);

  const raw = hpkeJweFragment;

  const onDropPrivateKey = async (files: File[]) => {
    try {
      const privateKey = JSON.parse(await files[0].text()) as Jwk;
      const jwe = decodeHpkeJweFragment(hpkeJweFragment);
      setMessage(new TextDecoder().decode(await hpkeDecrypt(jwe, privateKey)));
    } catch {
      toast.error("Decryption failed.", {
        description: "Wrong key, or the message is malformed.",
      });
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
          <FileDrop
            dragText="Drag the exported private key here"
            dropText="Drop to decrypt."
            onFilesAccepted={onDropPrivateKey}
          />
        )}
      </CardContent>
    </Card>
  );
}
