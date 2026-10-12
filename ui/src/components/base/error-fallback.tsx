"use client";

import { AlertTriangle, SearchX } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { buttonClass } from "./button";

/**
 * What a route group shows when rendering threw, or for a page that does not
 * exist. Keeps the frame the person was in (the layouts above still render)
 * and offers the two ways on: try again, or go to the surface's start.
 */
export function ErrorFallback({
  kind = "error",
  title,
  description,
  error,
  reset,
  homeHref = "/",
  homeLabel = "Go to the start",
  actions,
}: {
  kind?: "error" | "not-found";
  title?: string;
  description?: ReactNode;
  error?: Error & { digest?: string };
  reset?: () => void;
  homeHref?: string;
  homeLabel?: string;
  actions?: ReactNode;
}) {
  const notFound = kind === "not-found";
  const Icon = notFound ? SearchX : AlertTriangle;
  return (
    <div role={notFound ? undefined : "alert"} className="mx-auto flex max-w-md flex-col items-center gap-3 px-6 py-16 text-center">
      <span aria-hidden className={`flex size-12 items-center justify-center rounded-full ${notFound ? "bg-accent-soft text-accent-text" : "bg-danger-soft text-danger"}`}>
        <Icon className="size-6" />
      </span>
      <h1 className="text-xl font-semibold text-ink">{title ?? (notFound ? "Page not found" : "Something went wrong")}</h1>
      <p className="text-body text-muted">
        {description ?? (notFound ? "There is nothing at this address. It may have moved, or the link may be wrong." : "The page could not be shown. Trying again usually helps; if it keeps happening, the error below says what failed.")}
      </p>
      {error?.message && !notFound && (
        <pre className="max-w-full overflow-x-auto rounded-[var(--radius)] bg-ground px-3 py-2 text-start font-mono text-caption text-muted">
          {error.message}
          {error.digest ? `\n(${error.digest})` : ""}
        </pre>
      )}
      <div className="mt-2 flex flex-wrap justify-center gap-2">
        {reset && (
          <button type="button" onClick={reset} className={buttonClass("primary", "md")}>
            Try again
          </button>
        )}
        <Link href={homeHref} className={buttonClass(reset ? "secondary" : "primary", "md", "no-underline")}>
          {homeLabel}
        </Link>
        {actions}
      </div>
    </div>
  );
}
