"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { completeSignIn } from "@/lib/oidc";
import { setSession } from "@/lib/session";

/**
 * Where rIDM sends the browser back to. Nothing is rendered for long: the code
 * is spent, the session opens, and the app replaces this URL with `/` so the
 * code never sits in history.
 *
 * The router does that, not `location.replace`: the tokens live in memory, and
 * a full page load would throw them away the moment they arrived.
 *
 * `window.location.search` is read directly rather than through
 * `useSearchParams`, which a static export would want wrapped in `<Suspense>`
 * for no gain here.
 */
export default function Callback() {
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const tokens = await completeSignIn(window.location.search);
        if (cancelled) return;
        // `null` means rIDM answered `login_required` to a silent attempt:
        // nobody is signed in, which is not an error.
        if (tokens) setSession(tokens);
        router.replace("/");
      } catch (e) {
        if (!cancelled) setError(String(e instanceof Error ? e.message : e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [router]);

  if (error) {
    return (
      <>
        <h1>Sign-in failed</h1>
        <p className="notice error">{error}</p>
        <p>
          <button onClick={() => router.replace("/")}>Start again</button>
        </p>
      </>
    );
  }
  return <p className="meta">Signing you in…</p>;
}
