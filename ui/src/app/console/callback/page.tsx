"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { Alert, Spinner } from "@/components/ui";
import { AuthError, completeLogin } from "@/lib/console/auth";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <Callback />
    </Suspense>
  );
}

/** Where the tenant sends the browser back with the authorization code. */
function Callback() {
  const params = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    completeLogin(params)
      .then(({ returnTo }) => window.location.replace(returnTo))
      .catch((e: unknown) => setError(e instanceof AuthError ? e.message : "Sign-in could not be completed."));
  }, [params]);

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-[24rem]">
        {error ? (
          <div className="flex flex-col gap-4">
            <Alert tone="error">{error}</Alert>
            <Link href="/console/" className="text-[0.9rem] text-link underline underline-offset-4">
              Back to sign-in
            </Link>
          </div>
        ) : (
          <Spinner label="Signing you in…" />
        )}
      </div>
    </div>
  );
}
