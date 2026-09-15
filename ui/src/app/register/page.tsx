"use client";

import { useCallback, useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { Captcha } from "@/components/captcha";
import { useErrorText } from "@/components/errors";
import { TermsLabel } from "@/components/terms-label";
import { Alert, Button, Checkbox, PasswordField, Spinner, TextField, Title } from "@/components/ui";
import { api, ApiError, tenantBase } from "@/lib/api";
import { pageUrl, useFlow, type Post } from "@/lib/flow";
import { usePageParams, WithParams } from "@/lib/params";
import { useTenant } from "@/lib/tenant";
import type { PublicFlow } from "@/lib/types";

const ACCEPTS = ["authenticate", "register", "verify_email", "done"] as const;

export default function Page() {
  return (
    <WithParams>
      <RegisterPage />
    </WithParams>
  );
}

function RegisterPage() {
  const p = usePageParams();
  const f = useFlow(p.tenant, p.flow, ACCEPTS);
  const { t } = useI18n();
  const errorText = useErrorText();
  return (
    <AuthShell slug={p.tenant} locale={f.flow?.locale} locales={f.flow?.locales}>
      {f.loading || f.redirected ? (
        <Spinner label={t("common.loading")} />
      ) : f.error || !f.flow ? (
        <Alert tone="error">{errorText(f.error) ?? t("common.expired")}</Alert>
      ) : f.flow.stage === "verify_email" ? (
        <AwaitVerification flow={f.flow} tenant={p.tenant} />
      ) : (
        <RegisterForm flow={f.flow} post={f.post} reload={f.reload} tenant={p.tenant} />
      )}
    </AuthShell>
  );
}

function RegisterForm({ flow, post, reload, tenant }: { flow: PublicFlow; post: Post; reload: () => Promise<void>; tenant: string | null }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const { tenant: info } = useTenant();
  const [email, setEmail] = useState(flow.login_hint?.includes("@") ? flow.login_hint : "");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [captcha, setCaptcha] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const onToken = useCallback((tok: string | null) => setCaptcha(tok), []);
  const needsTerms = Boolean(flow.terms_url || flow.privacy_url);

  if (info && !info.registration.enabled) {
    return (
      <>
        <Title>{t("register.title")}</Title>
        <Alert tone="error">{t("register.disabled")}</Alert>
        <p className="mt-4 text-center text-[0.875rem]">
          <a href={pageUrl("login", { tenant, flow: flow.id })} className="text-link hover:underline underline-offset-4">
            {t("register.sign_in")}
          </a>
        </p>
      </>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setFieldErrors({});
    try {
      await post("register", {
        email,
        username: username || null,
        password,
        terms_accepted: needsTerms ? accepted : true,
        captcha_token: captcha,
      });
    } catch (err) {
      const fe = err instanceof ApiError ? err.fieldErrors() : {};
      delete fe.captcha_token;
      setFieldErrors(fe);
      setError(Object.keys(fe).length ? null : errorText(err));
      setCaptcha(null);
      await reload();
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("login.subtitle", { client: flow.client.name })}>{t("register.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      <TextField label={t("common.email")} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" inputMode="email" error={fieldErrors.email} autoFocus required />
      <TextField
        label={`${t("common.username")} (${t("common.optional")})`}
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        autoComplete="username"
        error={fieldErrors.username}
      />
      <PasswordField label={t("common.password")} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" error={fieldErrors.password} required />
      {needsTerms && <Checkbox checked={accepted} onChange={(e) => setAccepted(e.target.checked)} label={<TermsLabel terms={flow.terms_url} privacy={flow.privacy_url} />} />}
      {flow.captcha && <Captcha challenge={flow.captcha} onToken={onToken} />}
      <Button type="submit" busy={busy} disabled={(needsTerms && !accepted) || (flow.captcha ? !captcha : false)}>
        {t("register.title")}
      </Button>
      <p className="text-center text-[0.875rem] text-muted">
        {t("register.have_account")}{" "}
        <a href={pageUrl("login", { tenant, flow: flow.id })} className="text-link hover:underline underline-offset-4">
          {t("register.sign_in")}
        </a>
      </p>
    </form>
  );
}

function AwaitVerification({ flow, tenant }: { flow: PublicFlow; tenant: string | null }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [state, setState] = useState<"idle" | "busy" | "sent" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const email = flow.user?.email ?? "";
  const resend = async () => {
    if (!tenant || !email) return;
    setState("busy");
    try {
      await api(`${tenantBase(tenant)}/verification/email/resend`, { body: { identifier: email } });
      setState("sent");
    } catch (e) {
      setError(errorText(e));
      setState("error");
    }
  };
  return (
    <div className="flex flex-col gap-4">
      <Title>{t("verify.title")}</Title>
      <Alert tone="info">{t("register.verify_email_sent", { email })}</Alert>
      {state === "sent" && <Alert tone="ok">{t("verify.resent")}</Alert>}
      {state === "error" && error && <Alert tone="error">{error}</Alert>}
      <Button type="button" variant="secondary" busy={state === "busy"} onClick={() => void resend()}>
        {t("verify.resend")}
      </Button>
    </div>
  );
}
