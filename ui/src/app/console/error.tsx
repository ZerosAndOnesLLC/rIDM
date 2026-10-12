"use client";

import { ErrorFallback } from "@/components/base/error-fallback";

/** A console page threw while rendering: the shell stays up; offer a retry and the overview. */
export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <ErrorFallback error={error} reset={reset} homeHref="/console/" homeLabel="Go to the overview" />;
}
