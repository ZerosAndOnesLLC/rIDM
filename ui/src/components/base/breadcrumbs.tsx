import { ChevronRight } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

export interface Crumb {
  label: ReactNode;
  /** Omitted on the current page (the last crumb). */
  href?: string;
}

/** Where the page sits: `Users › ada.lovelace`. The last crumb is the page. */
export function Breadcrumbs({ items, className = "" }: { items: Crumb[]; className?: string }) {
  if (items.length === 0) return null;
  return (
    <nav aria-label="Breadcrumb" className={className}>
      <ol className="flex flex-wrap items-center gap-1.5 text-small text-muted">
        {items.map((c, i) => {
          const last = i === items.length - 1;
          return (
            <li key={i} className="flex min-w-0 items-center gap-1.5">
              {last || !c.href ? (
                <span aria-current={last ? "page" : undefined} className={`truncate ${last ? "font-medium text-ink" : ""}`}>
                  {c.label}
                </span>
              ) : (
                <Link href={c.href} className="truncate no-underline hover:text-ink hover:underline underline-offset-4">
                  {c.label}
                </Link>
              )}
              {!last && <ChevronRight className="rtl-flip size-3.5 shrink-0 text-faint" aria-hidden />}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
