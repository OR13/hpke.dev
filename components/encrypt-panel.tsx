"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { encrypt as hpkeEncrypt, type Jwk } from "@hpke-jose";
import { encrypt as coseEncrypt } from "@cose-hpke";
import { encodeHpkeJweFragment, encodeHpkeCoseFragment } from "@/services/hpke-url";
import { LockKeyIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

const DEFAULT_MESSAGE = `# Markdown Message
> ⌛ My lungs taste the air of Time Blown past falling sands ⌛
`;

type Format = "jose" | "cose";
type Mode = "integrated" | "keyEncryption";

export function EncryptPanel({ publicKeyJwk }: { publicKeyJwk: Jwk }) {
  const router = useRouter();
  const [message, setMessage] = React.useState(DEFAULT_MESSAGE);
  const [format, setFormat] = React.useState<Format>("jose");
  const [mode, setMode] = React.useState<Mode>("integrated");

  const encryptNow = async () => {
    try {
      const plaintext = new TextEncoder().encode(message);
      let fragment: string;
      if (format === "cose") {
        fragment = encodeHpkeCoseFragment(await coseEncrypt(plaintext, publicKeyJwk, { mode }));
      } else {
        const jwe = await hpkeEncrypt(plaintext, publicKeyJwk, {
          mode,
          protectedHeader: publicKeyJwk.kid ? { kid: publicKeyJwk.kid } : undefined,
        });
        fragment = encodeHpkeJweFragment(jwe);
      }
      router.push(`/decrypt#${fragment}`);
    } catch (e) {
      toast.error("Encryption failed.", { description: String(e) });
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <LockKeyIcon className="size-5" weight="fill" /> Compose message
            </CardTitle>
            <CardDescription>Encrypt to the recipient and get a shareable link.</CardDescription>
          </div>
          {publicKeyJwk.kid ? (
            <Badge variant="outline" className="max-w-[16rem] truncate font-normal">
              {publicKeyJwk.kid}
            </Badge>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          rows={8}
          spellCheck={false}
          className="resize-y font-mono text-sm"
        />

        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground">Envelope</span>
            <Tabs value={format} onValueChange={(v) => setFormat(v as Format)}>
              <TabsList>
                <TabsTrigger value="jose">JOSE</TabsTrigger>
                <TabsTrigger value="cose">COSE</TabsTrigger>
              </TabsList>
            </Tabs>
          </div>
          <div className="space-y-1">
            <span className="text-xs text-muted-foreground">Mode</span>
            <Tabs value={mode} onValueChange={(v) => setMode(v as Mode)}>
              <TabsList>
                <TabsTrigger value="integrated">Integrated</TabsTrigger>
                <TabsTrigger value="keyEncryption">Key Encryption</TabsTrigger>
              </TabsList>
            </Tabs>
          </div>
          <Button className="ml-auto" onClick={encryptNow}>
            <LockKeyIcon className="size-4" weight="bold" /> Encrypt &amp; get link
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
