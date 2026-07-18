import Link from "next/link";
import { LockKeyIcon } from "@phosphor-icons/react/dist/ssr";

const LINKS = [
  { label: "draft-ietf-jose-hpke-encrypt", href: "https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/" },
  { label: "draft-ietf-cose-hpke", href: "https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/" },
  { label: "RFC 9180 (HPKE)", href: "https://www.rfc-editor.org/rfc/rfc9180.html" },
  { label: "panva/hpke", href: "https://github.com/panva/hpke" },
  { label: "GitHub", href: "https://github.com/OR13/hpke.dev" },
];

export function SiteFooter() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-5xl flex-col gap-4 px-4 py-10 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <LockKeyIcon className="size-4" weight="fill" />
          <span>HPKE.dev — interoperability testing for JOSE &amp; COSE HPKE.</span>
        </div>
        <nav className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          {LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              target="_blank"
              rel="noreferrer"
              className="text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              {l.label}
            </a>
          ))}
        </nav>
      </div>
    </footer>
  );
}
