"use client";

import { ErrorFallback } from "@/components/base/error-fallback";

/** A page threw while rendering: say so inside the root layout, offer a retry. */
export default function RootError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="min-h-screen">
      <ErrorFallback error={error} reset={reset} />
    </main>
  );
}
