"use client";

import { useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { CodeInput } from "@/components/code-input";
import { useErrorText } from "@/components/errors";
import { Alert, Button, Checkbox, Spinner, Title } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useFlow } from "@/lib/flow";
import { usePageParams, WithParams } from "@/lib/params";

const ACCEPTS = ["mfa", "done"] as const;

export default function Page() {
  return (
    <WithParams>
      <MfaPage />
    </WithParams>
  );
}

/** Second factor. The verify step arrives with Phase 7; the page already speaks its contract. */
function MfaPage() {
  const p = usePageParams();
  const f = useFlow(p.tenant, p.flow, ACCEPTS);
  const { t } = useI18n();
  const errorText = useErrorText();
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await f.post("mfa/verify", { code, remember_device: trust });
    } catch (err) {
      setError(err instanceof ApiError && err.status === 404 ? t("mfa.unavailable") : errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell slug={p.tenant} locale={f.flow?.locale} locales={f.flow?.locales}>
      {f.loading || f.redirected || !f.flow ? (
        f.error ? <Alert tone="error">{errorText(f.error)}</Alert> : <Spinner label={t("common.loading")} />
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-5">
          <Title sub={t("mfa.description")}>{t("mfa.title")}</Title>
          {f.flow.user && <p className="-mt-3 text-[0.875rem] text-muted">{t("common.signed_in_as", { username: f.flow.user.username })}</p>}
          {error && <Alert tone="error">{error}</Alert>}
          <CodeInput label={t("common.code")} value={code} onChange={setCode} autoFocus />
          <Checkbox label={t("mfa.trust_device")} checked={trust} onChange={(e) => setTrust(e.target.checked)} />
          <Button type="submit" busy={busy} disabled={code.length < 6}>
            {t("common.continue")}
          </Button>
          <button type="button" onClick={() => void f.post("cancel", {}).catch((e: unknown) => setError(errorText(e)))} className="self-center text-[0.8125rem] text-muted hover:text-ink hover:underline underline-offset-4">
            {t("common.cancel")}
          </button>
        </form>
      )}
    </AuthShell>
  );
}
