"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert, Spinner } from "@/components/ui";
import { accountAuth } from "@/lib/account/session";
import { AuthError } from "@/lib/console/auth";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <Callback />
    </Suspense>
  );
}

/** Where the tenant sends the browser back with the authorization code. */
function Callback() {
  const { t } = useI18n();
  const params = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    accountAuth
      .completeLogin(params)
      .then(({ returnTo }) => window.location.replace(returnTo))
      .catch((e: unknown) => setError(e instanceof AuthError ? e.message : t("account.sign_in_failed")));
  }, [params, t]);

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-[24rem]">
        {error ? (
          <div className="flex flex-col gap-4">
            <Alert tone="error">{error}</Alert>
            <Link href="/account/" className="text-[0.9rem] text-link underline underline-offset-4">
              {t("account.back_to_sign_in")}
            </Link>
          </div>
        ) : (
          <Spinner label={t("account.signing_in")} />
        )}
      </div>
    </div>
  );
}
