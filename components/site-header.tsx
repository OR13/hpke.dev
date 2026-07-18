"use client";

import Link from "next/link";
import { LockKeyIcon, GithubLogoIcon, ListIcon } from "@phosphor-icons/react";

import { cn } from "@/lib/utils";
import { Button, buttonVariants } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme-toggle";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const NAV = [
  { label: "Encrypt", href: "/encrypt" },
  { label: "Decrypt", href: "/decrypt" },
  { label: "About", href: "/about" },
];

const REPO = "https://github.com/OR13/hpke.dev";

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-14 max-w-5xl items-center gap-2 px-4">
        <Link href="/" className="mr-4 flex items-center gap-2 font-heading font-bold">
          <LockKeyIcon className="size-5" weight="fill" />
          <span>HPKE.dev</span>
        </Link>

        <nav className="hidden items-center gap-1 sm:flex">
          {NAV.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-1">
          <a
            href={REPO}
            target="_blank"
            rel="noreferrer"
            aria-label="GitHub repository"
            className={cn(buttonVariants({ variant: "ghost", size: "icon" }))}
          >
            <GithubLogoIcon className="size-5" weight="bold" />
          </a>
          <ThemeToggle />

          <div className="sm:hidden">
            <DropdownMenu>
              <DropdownMenuTrigger
                render={
                  <Button variant="ghost" size="icon" aria-label="Menu">
                    <ListIcon className="size-5" weight="bold" />
                  </Button>
                }
              />
              <DropdownMenuContent align="end">
                {NAV.map((item) => (
                  <DropdownMenuItem
                    key={item.href}
                    render={<Link href={item.href}>{item.label}</Link>}
                  />
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </div>
    </header>
  );
}
