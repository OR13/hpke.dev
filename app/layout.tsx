import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { cn } from "@/lib/utils";

import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";

const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });
const sans = Inter({ subsets: ["latin"], variable: "--font-sans" });

export const metadata: Metadata = {
  metadataBase: new URL("https://hpke.dev"),
  title: {
    default: "HPKE.dev — Hybrid Public Key Encryption for JOSE & COSE",
    template: "%s — HPKE.dev",
  },
  description:
    "Interactive HPKE playground. Encrypt a message to a public key and share it as a link — an implementation of draft-ietf-jose-hpke-encrypt (Integrated and Key Encryption) built on panva/hpke.",
  openGraph: {
    title: "HPKE.dev",
    description:
      "Encrypt a message to a public key and share it as a link. HPKE for JOSE & COSE.",
    url: "https://hpke.dev",
    siteName: "HPKE.dev",
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={cn("font-mono", mono.variable, sans.variable)}
    >
      <body className="antialiased">
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          {children}
          <Toaster richColors position="bottom-right" />
        </ThemeProvider>
      </body>
    </html>
  );
}
