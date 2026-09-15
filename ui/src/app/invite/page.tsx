"use client";

import { useEffect, useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { useErrorText } from "@/components/errors";
import { Alert, Button, PasswordField, Spinner, TextField, Title } from "@/components/ui";
import { api, ApiError, tenantBase } from "@/lib/api";
import { pageUrl, STAGE_PAGE } from "@/lib/flow";
import { navigate, usePageParams, WithParams } from "@/lib/params";
import type { FlowStage, PublicInvitation } from "@/lib/types";

export default function Page() {
  return (
    <WithParams>
      <InvitePage />
    </WithParams>
  );
}

function InvitePage() {
  const p = usePageParams();
  const token = p.get("token");
  const { t } = useI18n();
  const errorText = useErrorText();
  const [inv, setInv] = useState<PublicInvitation | null>(null);
  const [broken, setBroken] = useState(false);
  const invalid = broken || !p.tenant || !token;
  const [loadError, setLoadError] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!p.tenant || !token) return;
    const ctrl = new AbortController();
    api<PublicInvitation>(`${tenantBase(p.tenant)}/invitations/${encodeURIComponent(token)}`, { signal: ctrl.signal })
      .then(setInv)
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        if (e instanceof ApiError && (e.status === 404 || e.status === 410 || e.status === 400)) setBroken(true);
        else setLoadError(errorText(e));
      });
    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- errorText is stable per locale
  }, [p.tenant, token]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!p.tenant || !token || !inv) return;
    setBusy(true);
    setError(null);
    setFieldErrors({});
    try {
      const res = await api<{ accepted: boolean; finish_url?: string; stage?: FlowStage; id?: string }>(
        `${tenantBase(p.tenant)}/invitations/${encodeURIComponent(token)}`,
        { body: { email: inv.email, username: username || null, password, terms_accepted: true, flow: p.flow } },
      );
      if (res.finish_url) return navigate(res.finish_url);
      if (res.stage && p.flow) return navigate(pageUrl(STAGE_PAGE[res.stage], { tenant: p.tenant, flow: p.flow }));
      setDone(true);
    } catch (err) {
      const fe = err instanceof ApiError ? err.fieldErrors() : {};
      setFieldErrors(fe);
      setError(Object.keys(fe).length ? null : errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell slug={p.tenant}>
      {invalid ? (
        <>
          <Title>{t("invite.title")}</Title>
          <Alert tone="error">{t("invite.invalid")}</Alert>
        </>
      ) : loadError ? (
        <Alert tone="error">{loadError}</Alert>
      ) : done ? (
        <>
          <Title>{t("invite.title")}</Title>
          <Alert tone="ok">{t("invite.done")}</Alert>
        </>
      ) : !inv ? (
        <Spinner label={t("common.loading")} />
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-4">
          <Title sub={inv.invited_by ? t("invite.description", { inviter: inv.invited_by, tenant: inv.tenant }) : t("invite.for", { email: inv.email })}>
            {t("invite.title")}
          </Title>
          {error && <Alert tone="error">{error}</Alert>}
          <TextField label={t("common.email")} value={inv.email} readOnly />
          <TextField label={`${t("common.username")} (${t("common.optional")})`} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" error={fieldErrors.username} autoFocus />
          <PasswordField label={t("common.password")} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" error={fieldErrors.password} required />
          <Button type="submit" busy={busy}>
            {t("invite.accept")}
          </Button>
        </form>
      )}
    </AuthShell>
  );
}
