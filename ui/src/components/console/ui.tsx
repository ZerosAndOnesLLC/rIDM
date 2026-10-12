"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { buttonClass, iconButtonClass } from "@/components/base/button";
import { avatarGradient, fmtNumber, initials } from "@/lib/console/format";

export function Card({ title, children, className = "", actions, padded = true, id }: { title?: ReactNode; children: ReactNode; className?: string; actions?: ReactNode; padded?: boolean; id?: string }) {
  return (
    <section id={id} className={`min-w-0 scroll-mt-20 rounded-[var(--radius)] border border-line bg-paper ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b border-line px-4 py-3">
          <h2 className="min-w-0 text-md font-semibold text-ink">{title}</h2>
          {actions && <div className="flex min-w-0 flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? "px-4 py-4" : ""}>{children}</div>
    </section>
  );
}

/**
 * Page title row. `count` sits beside the title as a mono pill (a list's
 * total); `sub` is one line under it; `actions` sit at the end and, on a
 * phone, the primary one stretches while the rest wrap.
 */
export function PageHeader({ title, sub, actions, count }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; count?: number }) {
  return (
    <header className="mb-4 flex flex-wrap items-end justify-between gap-x-4 gap-y-3">
      <div className="min-w-0">
        <h1 className="flex flex-wrap items-baseline gap-2.5 text-2xl font-semibold leading-none text-ink">
          <span className="min-w-0">{title}</span>
          {count !== undefined && <span className="rounded-full bg-accent-soft-2 px-2 py-1 font-mono text-small font-medium leading-none tracking-normal text-accent-text">{fmtNumber(count)}</span>}
        </h1>
        {sub && <p className="mt-1.5 text-small text-muted">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-1.5">{actions}</div>}
    </header>
  );
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" | "ok" | "warn" | "danger" | "contrast" }) {
  const cls = {
    neutral: "border border-line bg-ground text-muted",
    accent: "bg-accent-soft-2 text-accent-text",
    contrast: "bg-contrast-soft-2 text-contrast-text",
    ok: "bg-ok-soft text-ok",
    warn: "bg-warn-soft text-warn",
    danger: "bg-danger-soft text-danger",
  }[tone];
  return <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-caption font-medium ${cls}`}>{children}</span>;
}

/**
 * A state word with its mark: a dot with a halo in Signal v2, an outlined
 * pill in Signal, a plain dot in Vault and Registry (globals.css `.status`).
 */
export function Status({ tone, children }: { tone: "ok" | "warn" | "danger" | "accent" | "neutral"; children: ReactNode }) {
  return (
    <span className="status" data-tone={tone}>
      {children}
    </span>
  );
}

/** Gradient initials for a person, group or tenant. */
export function Avatar({ name, size = "md", className = "" }: { name: string; size?: "sm" | "md" | "lg"; className?: string }) {
  const box = size === "sm" ? "size-[1.375rem] text-[0.5625rem]" : size === "lg" ? "size-11 text-body" : "size-7 text-[0.625rem]";
  return (
    <span aria-hidden className={`inline-flex shrink-0 items-center justify-center rounded-full font-bold tracking-wide text-white ${box} ${className}`} style={{ background: avatarGradient(name) }}>
      {initials(name)}
    </span>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd>{children}</kbd>;
}

export function IconButton({ label, className = "", children, size = "md", ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; size?: "sm" | "md" }) {
  return (
    <button type="button" aria-label={label} title={label} className={iconButtonClass(size, className)} {...rest}>
      {children}
    </button>
  );
}

/** Toolbar button; `primary` for the one main action, `sm` inside rows. */
export function Button({ variant = "secondary", size = "md", className = "", children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "quiet"; size?: "sm" | "md" }) {
  return (
    <button type="button" className={buttonClass(variant, size, className)} {...rest}>
      {children}
    </button>
  );
}

/** Definition list row, for detail cards. */
export function Row({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 text-body not-last:border-b not-last:border-line">
      <dt className="shrink-0 text-muted">{label}</dt>
      <dd className="min-w-0 max-w-full truncate text-end text-ink [&>*]:max-w-full [&>*]:truncate">{children}</dd>
    </div>
  );
}

/** A small rounded tag: a group path, a scope, a client name in a feed. */
export function Chip({ children, mono = false, className = "" }: { children: ReactNode; mono?: boolean; className?: string }) {
  return <span className={`inline-flex items-center gap-1.5 rounded-full border border-line bg-ground px-2 py-0.5 text-caption text-ink-2 ${mono ? "font-mono" : ""} ${className}`}>{children}</span>;
}

/**
 * Modal on top of the console. Radix handles focus trapping, escape and
 * the accessible name; the description is optional.
 */
export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  hideTitle = false,
  size = "md",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  /** Keep the title for assistive tech only (command palette). */
  hideTitle?: boolean;
  size?: "md" | "lg";
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-[rgba(8,10,14,0.45)] backdrop-blur-[2px]" />
        <Dialog.Content
          className={`fixed inset-x-4 top-[12vh] z-50 mx-auto flex max-h-[76vh] flex-col overflow-hidden rounded-[var(--radius-lg)] border border-line bg-paper shadow-pop ${
            size === "lg" ? "max-w-2xl" : "max-w-lg"
          }`}
        >
          <Dialog.Title className={hideTitle ? "sr-only" : "px-5 pt-4 text-md font-semibold text-ink"}>{title}</Dialog.Title>
          {description ? (
            <Dialog.Description className={hideTitle ? "sr-only" : "px-5 pt-1 text-body text-muted"}>{description}</Dialog.Description>
          ) : (
            <Dialog.Description className="sr-only">{title}</Dialog.Description>
          )}
          {!hideTitle && (
            <Dialog.Close asChild>
              <IconButton label="Close" className="absolute end-2 top-2">
                <X className="size-4" aria-hidden />
              </IconButton>
            </Dialog.Close>
          )}
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

