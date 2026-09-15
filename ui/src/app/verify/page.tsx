"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { useErrorText } from "@/components/errors";
import { Alert, Button, Spinner, TextField, Title } from "@/components/ui";
import { api, ApiError, tenantBase } from "@/lib/api";
import { pageUrl, STAGE_PAGE } from "@/lib/flow";
import { navigate, usePageParams, WithParams } from "@/lib/params";
import type { FlowStage } from "@/lib/types";

export default function Page() {
  return (
    <WithParams>
      <VerifyPage />
    </WithParams>
  );
}

type Phase = "verifying" | "done" | "invalid" | "error" | "no_token";

function VerifyPage() {
  const p = usePageParams();
  const token = p.get("token");
  const { t } = useI18n();
  const errorText = useErrorText();
  const [phase, setPhase] = useState<Phase>(token ? "verifying" : "no_token");
  const [error, setError] = useState<string | null>(null);

  // The token is single-use: redeem it exactly once, even under strict-mode
  // double effects, and never abort the request once sent.
  const started = useRef<string | null>(null);
  useEffect(() => {
    if (!p.tenant || !token || started.current === token) return;
    started.current = token;
    api<{ verified: boolean; finish_url?: string; stage?: FlowStage; id?: string }>(`${tenantBase(p.tenant)}/verification/email/confirm`, {
      body: { token },
    })
      .then((res) => {
        if (res.finish_url) return navigate(res.finish_url);
        if (res.stage && p.flow) return navigate(pageUrl(STAGE_PAGE[res.stage], { tenant: p.tenant, flow: p.flow }));
        setPhase("done");
      })
      .catch((e: unknown) => {
        if (e instanceof ApiError && e.status < 500 && e.status !== 429) setPhase("invalid");
        else {
          setError(errorText(e));
          setPhase("error");
        }
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- errorText is stable per locale
  }, [p.tenant, p.flow, token]);

  return (
    <AuthShell slug={p.tenant}>
      <Title>{t("verify.title")}</Title>
      {phase === "verifying" && <Spinner label={t("verify.verifying")} />}
      {phase === "done" && <Alert tone="ok">{t("verify.done")}</Alert>}
      {phase === "no_token" && <Alert tone="error">{t("verify.no_token")}</Alert>}
      {phase === "error" && error && <Alert tone="error">{error}</Alert>}
      {phase === "invalid" && <Resend tenant={p.tenant} />}
    </AuthShell>
  );
}

function Resend({ tenant }: { tenant: string | null }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!tenant) return;
    setBusy(true);
    setError(null);
    try {
      await api(`${tenantBase(tenant)}/verification/email/resend`, { body: { identifier: email } });
      setSent(true);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Alert tone="error">{t("verify.invalid")}</Alert>
      {sent ? (
        <Alert tone="ok">{t("verify.resent")}</Alert>
      ) : (
        <>
          {error && <Alert tone="error">{error}</Alert>}
          <TextField label={t("common.email")} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
          <Button type="submit" busy={busy}>
            {t("verify.resend")}
          </Button>
        </>
      )}
    </form>
  );
}
