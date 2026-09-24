"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { Captcha } from "@/components/captcha";
import { CodeInput } from "@/components/code-input";
import { useErrorText } from "@/components/errors";
import { Alert, Button, Checkbox, Divider, PasswordField, TextField, Title } from "@/components/ui";
import { ApiError, tenantBase } from "@/lib/api";
import { pageUrl, type Post } from "@/lib/flow";
import { navigate } from "@/lib/params";
import { assertPasskey, passkeysSupported } from "@/lib/passkeys";
import type { Method, PasskeyRequestOptions, PublicFlow } from "@/lib/types";

type Passwordless = Exclude<Method, "password" | "passkey">;
const SEND_STEP: Record<Passwordless, string> = {
  magic_link: "magic-link",
  email_otp: "email-otp",
  sms_otp: "sms-otp",
};

const noop = () => () => {};

/** Whether this browser can run a passkey ceremony (false during server rendering). */
function usePasskeySupport(): boolean {
  return useSyncExternalStore(noop, passkeysSupported, () => false);
}

const BROKER_ERRORS = ["denied", "upstream", "invalid_state", "email_in_use", "already_linked", "account_disabled"] as const;

/** The login page's text for a Kerberos step that did not sign in. */
function kerberosError(e: unknown): string | null {
  if (!(e instanceof ApiError)) return null;
  // Still 401 after the browser's turn: it had no ticket to offer.
  if (e.status === 401) return "login.kerberos.no_ticket";
  switch (e.code) {
    case "kerberos_ntlm":
    case "kerberos_unsupported":
      return "login.kerberos.no_ticket";
    case "kerberos_invalid":
    case "kerberos_replay":
      return "login.kerberos.invalid";
    case "kerberos_no_account":
      return "login.kerberos.no_account";
    case "account_disabled":
      return "login.broker.account_disabled";
  }
  return null;
}

export function Authenticate({
  flow,
  post,
  reload,
  magic,
  tenant,
  preview = false,
  brokerError = null,
}: {
  flow: PublicFlow;
  post: Post;
  reload: () => Promise<void>;
  magic: string | null;
  tenant: string | null;
  /** Framed in the console: never grab focus (it would scroll the editor). */
  preview?: boolean;
  /** `?broker_error=` after an upstream sign-in stopped. */
  brokerError?: string | null;
}) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const passkeySupported = usePasskeySupport();
  // Passkeys are a button, not a form: the browser runs the ceremony.
  const passkey = flow.methods.includes("passkey") && passkeySupported;
  const methods = flow.methods.filter((m) => m !== "passkey");
  const [method, setMethod] = useState<Method>(methods.includes("password") ? "password" : (methods[0] ?? "password"));
  const [identifier, setIdentifier] = useState(flow.login_hint ?? "");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [captcha, setCaptcha] = useState<string | null>(null);
  const [busy, setBusy] = useState(Boolean(magic));
  const [error, setError] = useState<string | null>(() =>
    brokerError ? t(BROKER_ERRORS.includes(brokerError as (typeof BROKER_ERRORS)[number]) ? `login.broker.${brokerError}` : "login.broker.upstream") : null,
  );
  const [sent, setSent] = useState<Passwordless | null>(null);
  const [code, setCode] = useState("");
  const onToken = useCallback((tok: string | null) => setCaptcha(tok), []);

  const { negotiating, signIn: signInWithKerberos } = useKerberos({ flow, post, preview, magic, remember, setBusy, setError });
  const providers = flow.identity_providers ?? [];
  const kerberosLabel = flow.kerberos?.display_name ?? null;
  const providerVariant = methods.length === 0 && !passkey ? "primary" : "secondary";
  const providerButtons = [
    ...(kerberosLabel
      ? [
          <Button key="kerberos" type="button" variant={providerVariant} disabled={busy} onClick={() => void signInWithKerberos()}>
            {t("login.with_provider", { name: kerberosLabel })}
          </Button>,
        ]
      : []),
    ...providers.map((idp) => (
      <Button key={idp.alias} type="button" variant={providerVariant} disabled={busy} onClick={() => tenant && navigate(`${tenantBase(tenant)}/broker/${encodeURIComponent(idp.alias)}/start?flow=${encodeURIComponent(flow.id)}`)}>
        {t("login.with_provider", { name: idp.display_name })}
      </Button>
    )),
  ];
  const hasProviders = providerButtons.length > 0;

  // Opened from a magic-link email: redeem the token straight away (once).
  const magicStarted = useRef(false);
  useEffect(() => {
    if (!magic || magicStarted.current) return;
    magicStarted.current = true;
    post("magic-link/verify", { token: magic, remember_device: false })
      .catch((e: unknown) => setError(errorText(e)))
      .finally(() => setBusy(false));
  }, [magic, post, errorText]);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
      setCaptcha(null);
      await reload();
    } finally {
      setBusy(false);
    }
  }

  const submitPassword = (e: FormEvent) => {
    e.preventDefault();
    void run(() => post("password", { identifier, password, remember_device: remember, captcha_token: captcha }));
  };
  const send = (m: Passwordless) =>
    run(async () => {
      await post<{ sent: boolean }>(SEND_STEP[m], { identifier, captcha_token: captcha });
      setSent(m);
      setCode("");
    });
  const verify = (e: FormEvent) => {
    e.preventDefault();
    if (!sent) return;
    void run(() => post(`${SEND_STEP[sent]}/verify`, { code, remember_device: remember }));
  };
  const cancel = () => run(() => post<{ redirect_to: string }>("cancel", {}));
  const signInWithPasskey = () =>
    run(async () => {
      const options = await post<PasskeyRequestOptions>("passkey/start", {});
      const credential = await assertPasskey(options);
      await post("passkey/finish", { credential, remember_device: remember });
    });

  const subtitle = t("login.subtitle", { client: flow.client.name });
  const cancelLink = (
    <button type="button" onClick={() => void cancel()} className="self-center text-[0.8125rem] text-muted hover:text-ink hover:underline underline-offset-4">
      {t("common.cancel")}
    </button>
  );
  const passkeyButton = passkey && (
    <Button type="button" variant={methods.length === 0 ? "primary" : "secondary"} busy={busy} onClick={() => void signInWithPasskey()}>
      {t("login.passkey")}
    </Button>
  );

  if (methods.length === 0) {
    return (
      <div className="flex flex-col gap-5">
        <Title sub={subtitle}>{t("login.title")}</Title>
        {error && <Alert tone="error">{error}</Alert>}
        {negotiating && <Alert tone="info">{t("login.kerberos.checking")}</Alert>}
        {passkey || hasProviders ? (
          <>
            {passkey && <Checkbox label={t("login.remember_device")} checked={remember} onChange={(e) => setRemember(e.target.checked)} />}
            {passkeyButton}
            {providerButtons}
            {cancelLink}
          </>
        ) : (
          <Alert tone="error">{t("login.no_methods")}</Alert>
        )}
      </div>
    );
  }

  if (sent) {
    return (
      <CodeSent
        sent={sent}
        identifier={identifier}
        error={error}
        busy={busy}
        code={code}
        onCode={setCode}
        remember={remember}
        onRemember={setRemember}
        onVerify={verify}
        onResend={() => void send(sent)}
        onBack={() => {
          setSent(null);
          setError(null);
        }}
      />
    );
  }

  const others = methods.filter((m) => m !== method);
  const identifierField = (
    <TextField
      label={method === "sms_otp" ? t("common.phone") : method === "password" ? t("common.identifier") : t("common.email")}
      value={identifier}
      onChange={(e) => setIdentifier(e.target.value)}
      name="identifier"
      autoComplete={method === "sms_otp" ? "tel" : method === "password" ? "username" : "email"}
      inputMode={method === "sms_otp" ? "tel" : method === "password" ? "text" : "email"}
      autoFocus={!preview && !flow.login_hint}
      required
    />
  );

  return (
    <div className="flex flex-col gap-5">
      <Title sub={subtitle}>{t("login.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      {negotiating && <Alert tone="info">{t("login.kerberos.checking")}</Alert>}
      {flow.captcha && !error && flow.attempts > 0 && <Alert tone="info">{t("login.captcha_required")}</Alert>}

      {method === "password" ? (
        <form onSubmit={submitPassword} className="flex flex-col gap-4">
          {identifierField}
          <PasswordField
            label={t("common.password")}
            name="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            autoFocus={!preview && Boolean(flow.login_hint)}
            required
          />
          {flow.captcha && <Captcha challenge={flow.captcha} onToken={onToken} />}
          <Checkbox label={t("login.remember_device")} checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          <Button id="login-submit" type="submit" busy={busy} disabled={flow.captcha ? !captcha : false}>
            {t("common.continue")}
          </Button>
          <div className="flex flex-wrap justify-between gap-3 text-[0.875rem]">
            <a href={pageUrl("recover", { tenant, identifier })} className="text-link hover:underline underline-offset-4">
              {t("login.forgot_password")}
            </a>
            <span className="text-muted">
              {t("login.no_account")}{" "}
              <a href={pageUrl("register", { tenant, flow: flow.id })} className="text-link hover:underline underline-offset-4">
                {t("login.create_account")}
              </a>
            </span>
          </div>
        </form>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send(method as Passwordless);
          }}
          className="flex flex-col gap-4"
        >
          {identifierField}
          {flow.captcha && <Captcha challenge={flow.captcha} onToken={onToken} />}
          <Button type="submit" busy={busy} disabled={flow.captcha ? !captcha : false}>
            {method === "magic_link" ? t("login.send_link") : t("login.send_code")}
          </Button>
        </form>
      )}

      {(others.length > 0 || passkey || hasProviders) && (
        <>
          <Divider label={t("login.or")} />
          <div className="flex flex-col gap-2">
            {passkeyButton}
            {providerButtons}
            {others.map((m) => (
              <Button
                key={m}
                type="button"
                variant="secondary"
                onClick={() => {
                  setMethod(m);
                  setError(null);
                }}
              >
                {t(`login.${m === "password" ? "with_password" : m}`)}
              </Button>
            ))}
          </div>
        </>
      )}

      {cancelLink}
    </div>
  );
}

/** Kerberos desktop sign-in: asked once on its own when the page opens (the
 * server challenges only a browser on the tenant's trusted networks, and a
 * browser without a ticket gives up quietly: 204, or a final 401), and again
 * from its button. */
function useKerberos({
  flow,
  post,
  preview,
  magic,
  remember,
  setBusy,
  setError,
}: {
  flow: PublicFlow;
  post: Post;
  preview: boolean;
  magic: string | null;
  remember: boolean;
  setBusy: (b: boolean) => void;
  setError: (e: string | null) => void;
}) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [negotiating, setNegotiating] = useState(false);
  const started = useRef(false);
  const offered = Boolean(flow.kerberos);
  useEffect(() => {
    if (!offered || preview || magic || started.current) return;
    started.current = true;
    setNegotiating(true);
    post("kerberos", { auto: true })
      .catch((e: unknown) => {
        // Only a ticket that named nobody (or a disabled account) is worth
        // saying: every other failure means "no desktop sign-in here".
        const key = kerberosError(e);
        if (key === "login.kerberos.no_account" || key === "login.broker.account_disabled") setError(t(key));
      })
      .finally(() => setNegotiating(false));
  }, [offered, preview, magic, post, t, setError]);
  async function signIn() {
    setBusy(true);
    setError(null);
    try {
      await post("kerberos", { auto: false, remember_device: remember });
    } catch (e) {
      const key = kerberosError(e);
      setError(key ? t(key) : errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return { negotiating, signIn };
}

/** After a code or link was sent: the code entry (or the wait for the link). */
function CodeSent({
  sent,
  identifier,
  error,
  busy,
  code,
  onCode,
  remember,
  onRemember,
  onVerify,
  onResend,
  onBack,
}: {
  sent: Passwordless;
  identifier: string;
  error: string | null;
  busy: boolean;
  code: string;
  onCode: (c: string) => void;
  remember: boolean;
  onRemember: (r: boolean) => void;
  onVerify: (e: FormEvent) => void;
  onResend: () => void;
  onBack: () => void;
}) {
  const { t } = useI18n();
  const otp = sent !== "magic_link";
  return (
    <form onSubmit={onVerify} className="flex flex-col gap-5">
      <Title sub={otp ? t("login.code_sent", { destination: identifier, minutes: 10 }) : t("login.link_sent", { minutes: 15 })}>
        {otp ? t("login.enter_code") : t("login.title")}
      </Title>
      {error && <Alert tone="error">{error}</Alert>}
      {otp && (
        <>
          <CodeInput label={t("common.code")} value={code} onChange={onCode} autoFocus />
          <Checkbox label={t("login.remember_device")} checked={remember} onChange={(e) => onRemember(e.target.checked)} />
          <Button type="submit" busy={busy} disabled={code.length < 6}>
            {t("common.continue")}
          </Button>
        </>
      )}
      <div className="flex flex-wrap justify-between gap-3 text-[0.875rem]">
        <button type="button" className="text-link hover:underline underline-offset-4" onClick={onResend} disabled={busy}>
          {t("login.resend")}
        </button>
        <button type="button" className="text-muted hover:text-ink hover:underline underline-offset-4" onClick={onBack}>
          {t("login.change_method")}
        </button>
      </div>
    </form>
  );
}
