"use client";

import { X } from "lucide-react";
import type { ReactNode } from "react";

/**
 * The floating bar that appears when rows are selected (design/README.md
 * "Lists"): the count in the contrast colour, the actions, and a way to
 * clear the selection. Renders nothing while nothing is selected.
 */
export function BulkBar({ count, label, onClear, children }: { count: number; label: string; onClear: () => void; children: ReactNode }) {
  if (count === 0) return null;
  return (
    <div role="region" aria-label={label} className="sticky bottom-3.5 z-20 mx-auto mt-3 flex w-max max-w-full flex-wrap items-center gap-2 rounded-full bg-bar py-1.5 ps-2 pe-1.5 text-small text-bar-ink shadow-pop">
      <span className="inline-flex min-w-6 items-center justify-center rounded-full bg-[var(--contrast-solid)] px-1.5 py-0.5 font-mono text-caption font-bold text-[var(--contrast-ink)]" aria-hidden>
        {count}
      </span>
      <span>
        <span className="sr-only">{count} </span>selected
      </span>
      {children}
      <button type="button" aria-label="Clear selection" onClick={onClear} className="flex size-7 items-center justify-center rounded-full text-bar-muted hover:bg-[var(--bar-field)] hover:text-bar-ink">
        <X className="size-4" aria-hidden />
      </button>
    </div>
  );
}

/** A button on the bulk bar: outlined on the dark pill. */
export const bulkButtonClass = (danger = false) =>
  `inline-flex min-h-7 items-center gap-1.5 whitespace-nowrap rounded-full border border-[var(--bar-line)] px-2.5 text-caption font-medium hover:bg-[var(--bar-field)] disabled:cursor-not-allowed disabled:opacity-60 ${danger ? "text-[#ffb4a8]" : "text-bar-ink"}`;
