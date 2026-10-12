"use client";

import { ErrorFallback } from "@/components/base/error-fallback";

/** An account page threw while rendering: the frame stays up; offer a retry and the profile. */
export default function AccountError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <ErrorFallback error={error} reset={reset} homeHref="/account/" homeLabel="Go to your profile" />;
}
