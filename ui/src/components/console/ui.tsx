"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { buttonClass, iconButtonClass } from "@/components/base/button";

export function Card({ title, children, className = "", actions }: { title?: ReactNode; children: ReactNode; className?: string; actions?: ReactNode }) {
  return (
    <section className={`min-w-0 rounded-[calc(var(--radius)+2px)] border border-line bg-paper ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="text-lead font-semibold text-ink">{title}</h2>
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
        <h1 className="text-2xl font-semibold leading-tight tracking-[-0.01em] text-ink">{title}</h1>
        {sub && <p className="mt-1 text-lead text-muted">{sub}</p>}
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
  return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-caption font-medium ${cls}`}>{children}</span>;
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
      className={iconButtonClass("md", className)}
      {...rest}
    >
      {children}
    </button>
  );
}

/** Small button for toolbars; `primary` for the one main action. */
export function Button({ variant = "secondary", className = "", children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  return (
    <button type="button" className={buttonClass(variant, "md", className)} {...rest}>
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
