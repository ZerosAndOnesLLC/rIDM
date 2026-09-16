"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { Captcha } from "@/components/captcha";
import { CodeInput } from "@/components/code-input";
import { useErrorText } from "@/components/errors";
import { TermsLabel } from "@/components/terms-label";
import { Alert, Button, Checkbox, Divider, PasswordField, Spinner, TextField, Title } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { pageUrl, useFlow, type Post } from "@/lib/flow";
import { usePageParams, WithParams } from "@/lib/params";
import { assertPasskey, passkeysSupported } from "@/lib/passkeys";
import { useTenant } from "@/lib/tenant";
import type { AttributeDef, Method, PasskeyRequestOptions, PublicFlow } from "@/lib/types";

const ACCEPTS = ["authenticate", "password_change", "profile", "terms", "done"] as const;

export default function Page() {
  return (
    <WithParams>
      <LoginPage />
    </WithParams>
  );
}

function LoginPage() {
  const p = usePageParams();
  if (p.get("preview") === "1") return <PreviewPage tenant={p.tenant} />;
  return <LivePage p={p} />;
}

/**
 * Inside the console's branding editor: the real page on a stand-in flow,
 * so every colour, logo, link and stylesheet change shows at once. Nothing
 * is submitted.
 */
function PreviewPage({ tenant }: { tenant: string | null }) {
  return (
    <AuthShell slug={tenant} preview>
      <PreviewForm tenant={tenant} />
    </AuthShell>
  );
}

function PreviewForm({ tenant }: { tenant: string | null }) {
  const { tenant: info } = useTenant();
  const { t } = useI18n();
  if (!info) return <Spinner label={t("common.loading")} />;
  const flow: PublicFlow = {
    id: "preview",
    stage: "authenticate",
    csrf: "",
    expires_at: "2099-01-01T00:00:00Z",
    client: { client_id: "preview", name: t("login.preview_client"), logo_uri: null, client_uri: null, tos_uri: null, policy_uri: null },
    methods: info.methods,
    login_hint: null,
    ui_locales: [],
    locale: info.locale.default,
    dir: "ltr",
    locales: info.locale.supported,
    pending_scopes: [],
    missing_attributes: [],
    terms_url: info.registration.terms_url,
    privacy_url: info.registration.privacy_url,
    user: null,
    attempts: 0,
    captcha: null,
    mfa: null,
  };
  const post: Post = <T,>() => new Promise<T>(() => {});
  return <Authenticate flow={flow} post={post} reload={() => Promise.resolve()} magic={null} tenant={tenant} preview />;
}

function LivePage({ p }: { p: ReturnType<typeof usePageParams> }) {
  const f = useFlow(p.tenant, p.flow, ACCEPTS);
  const { t } = useI18n();
  const errorText = useErrorText();
  return (
    <AuthShell slug={p.tenant} locale={f.flow?.locale} locales={f.flow?.locales}>
      {f.loading || f.redirected ? (
        <Spinner label={t("common.loading")} />
      ) : f.error || !f.flow ? (
        <Alert tone="error">{errorText(f.error) ?? t("common.expired")}</Alert>
      ) : f.flow.stage === "authenticate" ? (
        <Authenticate flow={f.flow} post={f.post} reload={f.reload} magic={p.get("magic")} tenant={p.tenant} />
      ) : f.flow.stage === "password_change" ? (
        <PasswordChange flow={f.flow} post={f.post} />
      ) : f.flow.stage === "profile" ? (
        <Profile flow={f.flow} post={f.post} />
      ) : f.flow.stage === "terms" ? (
        <Terms flow={f.flow} post={f.post} />
      ) : (
        <Spinner label={t("common.loading")} />
      )}
    </AuthShell>
  );
}

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

function Authenticate({
  flow,
  post,
  reload,
  magic,
  tenant,
  preview = false,
}: {
  flow: PublicFlow;
  post: Post;
  reload: () => Promise<void>;
  magic: string | null;
  tenant: string | null;
  /** Framed in the console: never grab focus (it would scroll the editor). */
  preview?: boolean;
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
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<Passwordless | null>(null);
  const [code, setCode] = useState("");
  const onToken = useCallback((tok: string | null) => setCaptcha(tok), []);

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
        {passkey ? (
          <>
            <Checkbox label={t("login.remember_device")} checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            {passkeyButton}
            {cancelLink}
          </>
        ) : (
          <Alert tone="error">{t("login.no_methods")}</Alert>
        )}
      </div>
    );
  }

  if (sent) {
    const otp = sent !== "magic_link";
    return (
      <form onSubmit={verify} className="flex flex-col gap-5">
        <Title sub={otp ? t("login.code_sent", { destination: identifier, minutes: 10 }) : t("login.link_sent", { minutes: 15 })}>
          {otp ? t("login.enter_code") : t("login.title")}
        </Title>
        {error && <Alert tone="error">{error}</Alert>}
        {otp && (
          <>
            <CodeInput label={t("common.code")} value={code} onChange={setCode} autoFocus />
            <Checkbox label={t("login.remember_device")} checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            <Button type="submit" busy={busy} disabled={code.length < 6}>
              {t("common.continue")}
            </Button>
          </>
        )}
        <div className="flex flex-wrap justify-between gap-3 text-[0.875rem]">
          <button type="button" className="text-link hover:underline underline-offset-4" onClick={() => void send(sent)} disabled={busy}>
            {t("login.resend")}
          </button>
          <button
            type="button"
            className="text-muted hover:text-ink hover:underline underline-offset-4"
            onClick={() => {
              setSent(null);
              setError(null);
            }}
          >
            {t("login.change_method")}
          </button>
        </div>
      </form>
    );
  }

  const others = methods.filter((m) => m !== method);
  const identifierField = (
    <TextField
      label={method === "sms_otp" ? t("common.phone") : method === "password" ? t("common.identifier") : t("common.email")}
      value={identifier}
      onChange={(e) => setIdentifier(e.target.value)}
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
      {flow.captcha && !error && flow.attempts > 0 && <Alert tone="info">{t("login.captcha_required")}</Alert>}

      {method === "password" ? (
        <form onSubmit={submitPassword} className="flex flex-col gap-4">
          {identifierField}
          <PasswordField
            label={t("common.password")}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            autoFocus={!preview && Boolean(flow.login_hint)}
            required
          />
          {flow.captcha && <Captcha challenge={flow.captcha} onToken={onToken} />}
          <Checkbox label={t("login.remember_device")} checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          <Button type="submit" busy={busy} disabled={flow.captcha ? !captcha : false}>
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

      {(others.length > 0 || passkey) && (
        <>
          <Divider label={t("login.or")} />
          <div className="flex flex-col gap-2">
            {passkeyButton}
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

function PasswordChange({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mismatch = confirm.length > 0 && pw !== confirm;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (mismatch) return;
    setBusy(true);
    setError(null);
    try {
      await post("password-change", { new_password: pw });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("password_change.description")}>{t("password_change.title")}</Title>
      {flow.user && <p className="text-[0.875rem] text-muted">{t("common.signed_in_as", { username: flow.user.username })}</p>}
      {error && <Alert tone="error">{error}</Alert>}
      <PasswordField label={t("password_change.new_password")} value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" autoFocus required />
      <PasswordField
        label={t("password_change.confirm")}
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        autoComplete="new-password"
        error={mismatch ? t("password_change.mismatch") : null}
        required
      />
      <Button type="submit" busy={busy} disabled={mismatch || !pw}>
        {t("common.continue")}
      </Button>
    </form>
  );
}

function Profile({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const defs = [...flow.missing_attributes].sort((a, b) => a.order - b.order);
  const [values, setValues] = useState<Record<string, string | boolean>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("profile", { attributes: encode(defs, values) });
    } catch (err) {
      const fe = err instanceof ApiError ? err.fieldErrors() : {};
      setFieldErrors(fe);
      if (Object.keys(fe).length === 0) setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("profile.description")}>{t("profile.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      {defs.map((d) => (
        <AttributeInput key={d.name} def={d} value={values[d.name]} error={fieldErrors[d.name]} onChange={(v) => setValues((s) => ({ ...s, [d.name]: v }))} />
      ))}
      <Button type="submit" busy={busy}>
        {t("common.continue")}
      </Button>
    </form>
  );
}

function encode(defs: AttributeDef[], values: Record<string, string | boolean>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const d of defs) {
    const v = values[d.name];
    if (v === undefined || v === "") continue;
    if (d.type === "boolean") out[d.name] = Boolean(v);
    else if (d.type === "number") out[d.name] = Number(v);
    else if (d.type === "json") {
      try {
        out[d.name] = JSON.parse(String(v));
      } catch {
        out[d.name] = v;
      }
    } else if (d.multivalued)
      out[d.name] = String(v)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    else out[d.name] = v;
  }
  return out;
}

function AttributeInput({
  def,
  value,
  error,
  onChange,
}: {
  def: AttributeDef;
  value: string | boolean | undefined;
  error?: string;
  onChange: (v: string | boolean) => void;
}) {
  const { t } = useI18n();
  const label = `${def.label ?? def.name}${def.required ? "" : ` (${t("common.optional")})`}`;
  if (def.type === "boolean") {
    return <Checkbox label={label} checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />;
  }
  if (def.type === "enum") {
    return (
      <label className="flex flex-col gap-1.5 text-[0.8125rem] font-medium">
        {label}
        <select
          value={String(value ?? "")}
          onChange={(e) => onChange(e.target.value)}
          required={def.required}
          className="min-h-11 rounded-[var(--radius)] border border-line bg-paper px-3 text-[0.9375rem] font-normal text-ink"
        >
          <option value="">—</option>
          {def.validation.values.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </label>
    );
  }
  const type =
    def.type === "email" ? "email" : def.type === "url" ? "url" : def.type === "phone" ? "tel" : def.type === "date" ? "date" : def.type === "number" ? "number" : "text";
  return (
    <TextField
      label={label}
      type={type}
      value={String(value ?? "")}
      onChange={(e) => onChange(e.target.value)}
      required={def.required}
      minLength={def.validation.min_length ?? undefined}
      maxLength={def.validation.max_length ?? undefined}
      min={def.validation.min ?? undefined}
      max={def.validation.max ?? undefined}
      pattern={def.validation.pattern ?? undefined}
      hint={def.description}
      error={error}
    />
  );
}

function Terms({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("terms", { accepted: true });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("terms.description")}>{t("terms.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      <Checkbox checked={accepted} onChange={(e) => setAccepted(e.target.checked)} label={<TermsLabel terms={flow.terms_url} privacy={flow.privacy_url} />} />
      <Button type="submit" busy={busy} disabled={!accepted}>
        {t("terms.accept")}
      </Button>
      <button type="button" onClick={() => void post("cancel", {}).catch((e: unknown) => setError(errorText(e)))} className="self-center text-[0.8125rem] text-muted hover:text-ink hover:underline underline-offset-4">
        {t("common.cancel")}
      </button>
    </form>
  );
}
