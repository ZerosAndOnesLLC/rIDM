"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";

export function Card({ title, children, className = "", actions }: { title?: ReactNode; children: ReactNode; className?: string; actions?: ReactNode }) {
  return (
    <section className={`min-w-0 rounded-[calc(var(--radius)+2px)] border border-line bg-paper ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="text-[0.9375rem] font-semibold text-ink">{title}</h2>
          {actions}
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-[1.5rem] font-semibold leading-tight tracking-[-0.01em] text-ink">{title}</h1>
        {sub && <p className="mt-1 text-[0.9rem] text-muted">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" | "ok" | "danger" }) {
  const cls = {
    neutral: "bg-ground text-muted",
    accent: "bg-[color-mix(in_oklab,var(--accent)_14%,transparent)] text-link",
    ok: "bg-ok-soft text-ok",
    danger: "bg-danger-soft text-danger",
  }[tone];
  return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[0.75rem] font-medium ${cls}`}>{children}</span>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd>{children}</kbd>;
}

export function IconButton({ label, className = "", children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={`inline-flex size-9 items-center justify-center rounded-[var(--radius)] text-muted hover:bg-ground hover:text-ink ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}

/** Small button for toolbars; `primary` for the one main action. */
export function Button({ variant = "secondary", className = "", children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  const cls = {
    primary: "bg-accent text-accent-ink hover:brightness-110",
    secondary: "border border-line bg-paper text-ink hover:bg-ground",
    danger: "border border-line bg-paper text-danger hover:bg-danger-soft",
  }[variant];
  return (
    <button
      type="button"
      className={`inline-flex min-h-9 items-center justify-center gap-2 rounded-[var(--radius)] px-3.5 text-[0.875rem] font-medium disabled:cursor-not-allowed disabled:opacity-60 ${cls} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}

/** Definition list row, for detail cards. */
export function Row({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 text-[0.875rem] not-last:border-b not-last:border-line">
      <dt className="shrink-0 text-muted">{label}</dt>
      <dd className="min-w-0 max-w-full truncate text-end text-ink [&>*]:max-w-full [&>*]:truncate">{children}</dd>
    </div>
  );
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
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px]" />
        <Dialog.Content
          className={`fixed inset-x-4 top-[12vh] z-50 mx-auto flex max-h-[76vh] flex-col overflow-hidden rounded-[calc(var(--radius)+4px)] border border-line bg-paper shadow-2xl ${
            size === "lg" ? "max-w-2xl" : "max-w-lg"
          }`}
        >
          <Dialog.Title className={hideTitle ? "sr-only" : "px-5 pt-4 text-[1rem] font-semibold text-ink"}>{title}</Dialog.Title>
          {description ? (
            <Dialog.Description className={hideTitle ? "sr-only" : "px-5 pt-1 text-[0.875rem] text-muted"}>{description}</Dialog.Description>
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
