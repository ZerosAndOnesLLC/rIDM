"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { ArrowLeft, X } from "lucide-react";
import type { ReactNode } from "react";
import { IconButton } from "./ui";

/**
 * A detail that floats over its list (design/README.md "Detail"): a panel
 * at the end of the viewport with a tinted header, a stat strip, tabs, the
 * scrolling body and a footer for the save state and destructive actions.
 * It is a modal dialog (the list behind is inert, Escape and the scrim
 * close it), and its title is the page's h1 so a deep link reads the same.
 */
export function DetailPanel({
  open,
  onClose,
  title,
  sub,
  mark,
  actions,
  stats,
  tabs,
  footer,
  children,
  backLabel = "Back to the list",
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  /** Identifiers under the title (username · email · member since). */
  sub?: ReactNode;
  /** The avatar or tenant mark beside the title. */
  mark?: ReactNode;
  actions?: ReactNode;
  stats?: { label: string; value: ReactNode }[];
  tabs?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  backLabel?: string;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-[rgba(8,10,14,0.45)] backdrop-blur-[2px]" />
        <Dialog.Content
          aria-describedby={undefined}
          className="panel-in fixed inset-y-0 end-0 z-50 flex w-full flex-col overflow-hidden border-s border-line bg-paper shadow-pop sm:inset-y-2.5 sm:end-2.5 sm:w-[min(42rem,calc(100%-1.25rem))] sm:rounded-[var(--radius-lg)] sm:border"
        >
          <header className="flex items-start gap-3 border-b border-line bg-[linear-gradient(180deg,var(--accent-soft),var(--paper))] px-4 py-3.5 sm:items-center">
            <Dialog.Close asChild>
              <IconButton label={backLabel} className="shrink-0">
                <ArrowLeft className="rtl-flip size-4" aria-hidden />
              </IconButton>
            </Dialog.Close>
            {mark}
            <div className="min-w-0 flex-1">
              <Dialog.Title asChild>
                <h1 className="flex min-w-0 flex-wrap items-center gap-2.5 text-xl font-semibold leading-tight text-ink">{title}</h1>
              </Dialog.Title>
              {sub && <div className="mt-0.5 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 text-caption text-muted">{sub}</div>}
            </div>
            <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
              {actions}
              <Dialog.Close asChild>
                <IconButton label="Close">
                  <X className="size-4" aria-hidden />
                </IconButton>
              </Dialog.Close>
            </div>
          </header>
          {stats && stats.length > 0 && (
            <dl className="grid grid-cols-2 border-b border-line sm:grid-cols-4">
              {stats.map((s, i) => (
                <div key={s.label} className={`px-4 py-2.5 ${i % 2 === 0 ? "border-e border-line" : ""} ${i < stats.length - 2 ? "border-b border-line sm:border-b-0" : ""} sm:border-e sm:last:border-e-0`}>
                  <dt className="text-caption text-muted">{s.label}</dt>
                  <dd className="mt-0.5 flex items-center gap-1.5 text-small font-semibold text-ink">{s.value}</dd>
                </div>
              ))}
            </dl>
          )}
          {tabs}
          <div className="flex-1 overflow-y-auto px-4 pb-6 pt-4">{children}</div>
          {footer && <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-line bg-ground px-4 py-2.5">{footer}</footer>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** The panel's tabs: links, so a deep link opens the tab too. */
export function PanelTabs({ label, children }: { label: string; children: ReactNode }) {
  return (
    <nav aria-label={label} className="flex gap-0.5 overflow-x-auto border-b border-line px-3">
      {children}
    </nav>
  );
}

export const panelTabClass = (active: boolean) => `-mb-px whitespace-nowrap border-b-2 px-2.5 py-2.5 text-small no-underline ${active ? "border-accent-solid font-semibold text-ink" : "border-transparent text-muted hover:text-ink"}`;
