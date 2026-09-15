"use client";

import { useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { useErrorText } from "@/components/errors";
import { Alert, Button, PasswordField, TextField, Title } from "@/components/ui";
import { api, ApiError, tenantBase } from "@/lib/api";
import { usePageParams, WithParams } from "@/lib/params";

export default function Page() {
  return (
    <WithParams>
      <RecoverPage />
    </WithParams>
  );
}

function RecoverPage() {
  const p = usePageParams();
  const token = p.get("token");
  return (
    <AuthShell slug={p.tenant}>
      {token ? <SetNewPassword tenant={p.tenant} token={token} /> : <RequestLink tenant={p.tenant} initial={p.get("identifier") ?? ""} />}
    </AuthShell>
  );
}

function RequestLink({ tenant, initial }: { tenant: string | null; initial: string }) {
  const { t, locale } = useI18n();
  const errorText = useErrorText();
  const [identifier, setIdentifier] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!tenant) return;
    setBusy(true);
    setError(null);
    try {
      await api(`${tenantBase(tenant)}/recovery/password`, { body: { identifier, locale } });
      setSent(true);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  if (sent) {
    return (
      <>
        <Title>{t("recover.title")}</Title>
        <Alert tone="ok">{t("recover.sent", { identifier })}</Alert>
      </>
    );
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("recover.description")}>{t("recover.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      <TextField label={t("common.identifier")} value={identifier} onChange={(e) => setIdentifier(e.target.value)} autoComplete="username" autoFocus required />
      <Button type="submit" busy={busy}>
        {t("recover.send")}
      </Button>
    </form>
  );
}

function SetNewPassword({ tenant, token }: { tenant: string | null; token: string }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mismatch = confirm.length > 0 && pw !== confirm;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!tenant || mismatch) return;
    setBusy(true);
    setError(null);
    try {
      await api(`${tenantBase(tenant)}/recovery/password/confirm`, { body: { token, new_password: pw } });
      setDone(true);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 410) ) setInvalid(true);
      else setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  if (invalid) {
    return (
      <>
        <Title>{t("recover.title")}</Title>
        <Alert tone="error">{t("recover.invalid")}</Alert>
      </>
    );
  }
  if (done) {
    return (
      <>
        <Title>{t("recover.title")}</Title>
        <Alert tone="ok">{t("recover.done")}</Alert>
        <p className="mt-4 text-[0.875rem] text-muted">{t("recover.no_flow_hint")}</p>
      </>
    );
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title>{t("recover.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      <PasswordField label={t("recover.new_password")} value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" autoFocus required />
      <PasswordField label={t("password_change.confirm")} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" error={mismatch ? t("password_change.mismatch") : null} required />
      <Button type="submit" busy={busy} disabled={mismatch || !pw}>
        {t("common.continue")}
      </Button>
    </form>
  );
}
