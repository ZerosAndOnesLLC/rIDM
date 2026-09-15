"use client";

import { ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Alert, Button, TextField } from "@/components/ui";
import { AuthError, isValidSlug, lastTenant } from "@/lib/console/auth";
import { useConsole } from "@/lib/console/session";

/**
 * The signed-out state of every console page: pick the tenant to sign in
 * through, then the tenant's own login page takes over. Global
 * administrators live in `master`.
 */
export function SignIn({ error }: { error?: string | null }) {
  const { signIn, notice } = useConsole();
  const [tenant, setTenant] = useState(() => lastTenant() ?? "master");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const message = problem ?? error ?? notice;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const slug = tenant.trim().toLowerCase();
    if (!isValidSlug(slug)) {
      setProblem("Enter a tenant slug: lowercase letters, digits and hyphens.");
      return;
    }
    setBusy(true);
    setProblem(null);
    try {
      await signIn(slug);
    } catch (err) {
      setProblem(err instanceof AuthError ? err.message : "Sign-in could not be started.");
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-10">
      <div className="mb-6 flex items-center gap-2.5">
        <span aria-hidden className="flex size-9 items-center justify-center rounded-lg bg-accent text-accent-ink">
          <ShieldCheck className="size-5" />
        </span>
        <span className="text-[1.0625rem] font-semibold text-ink">rIDM Console</span>
      </div>
      <main className="card-in w-full max-w-[24rem] rounded-[calc(var(--radius)+4px)] border border-line bg-paper p-6 sm:p-8">
        <h1 className="text-[1.5rem] font-semibold leading-tight tracking-[-0.01em] text-ink">Sign in to the console</h1>
        <p className="mt-1.5 text-[0.9375rem] text-muted">You will sign in through your tenant&apos;s own login page.</p>
        <form onSubmit={submit} className="mt-6 flex flex-col gap-4" noValidate>
          {message && <Alert tone="error">{message}</Alert>}
          <TextField
            label="Tenant"
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            hint="Global administrators sign in through master."
            required
          />
          <Button type="submit" busy={busy}>
            Continue
          </Button>
        </form>
      </main>
      <p className="mt-6 text-[0.8125rem] text-muted">Secured by rIDM</p>
    </div>
  );
}
