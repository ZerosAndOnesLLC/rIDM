"use client";

import { useEffect, useState, useSyncExternalStore, type FormEvent } from "react";
import QRCode from "qrcode";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { CodeInput } from "@/components/code-input";
import { useErrorText } from "@/components/errors";
import { Alert, Button, Checkbox, Spinner, TextField, Title } from "@/components/ui";
import { useFlow } from "@/lib/flow";
import { usePageParams, WithParams } from "@/lib/params";
import { assertPasskey, createPasskey, passkeysSupported } from "@/lib/passkeys";
import type { MfaEnrolled, PasskeyCreationOptions, PasskeyRequestOptions, PublicFlow, TotpEnrolment } from "@/lib/types";

const ACCEPTS = ["mfa", "done"] as const;

export default function Page() {
  return (
    <WithParams>
      <MfaPage />
    </WithParams>
  );
}

const noop = () => () => {};

/** Whether this browser can run a passkey ceremony (false during server rendering). */
function usePasskeySupport(): boolean {
  return useSyncExternalStore(noop, passkeysSupported, () => false);
}

type Choice = "app" | "passkey";

/**
 * Second factor. A user with a factor verifies with it (an authenticator
 * code, a passkey, or a recovery code); one without enrols first, choosing
 * between an authenticator app and a passkey when the tenant offers both,
 * then sees the recovery codes once before the flow moves on.
 */
function MfaPage() {
  const p = usePageParams();
  const f = useFlow(p.tenant, p.flow, ACCEPTS);
  const { t } = useI18n();
  const errorText = useErrorText();
  const supported = usePasskeySupport();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [choice, setChoice] = useState<Choice | null>(null);

  let body;
  if (f.loading || f.redirected || !f.flow) {
    body = f.error ? <Alert tone="error">{errorText(f.error)}</Alert> : <Spinner label={t("common.loading")} />;
  } else if (codes) {
    body = <RecoveryCodes codes={codes} onDone={() => void f.reload()} />;
  } else if (f.flow.mfa?.enroll) {
    const passkeyOffered = f.flow.methods.includes("passkey") && supported;
    const chosen = passkeyOffered ? choice : "app";
    if (chosen === "passkey") {
      body = <EnrolPasskey flow={f.flow} post={f.post} onEnrolled={setCodes} onBack={() => setChoice(null)} />;
    } else if (chosen === "app") {
      body = <Enrol flow={f.flow} post={f.post} onEnrolled={setCodes} onBack={passkeyOffered ? () => setChoice(null) : null} />;
    } else {
      body = <Choose flow={f.flow} post={f.post} onChoose={setChoice} />;
    }
  } else {
    body = <Verify flow={f.flow} post={f.post} passkeys={supported} />;
  }

  return (
    <AuthShell slug={p.tenant} locale={f.flow?.locale} locales={f.flow?.locales}>
      {body}
    </AuthShell>
  );
}

type Post = ReturnType<typeof useFlow>["post"];

function CancelLink({ post }: { post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [error, setError] = useState<string | null>(null);
  return (
    <>
      {error && <Alert tone="error">{error}</Alert>}
      <button
        type="button"
        onClick={() => void post("cancel", {}).catch((e: unknown) => setError(errorText(e)))}
        className="self-center text-[0.8125rem] text-muted hover:text-ink hover:underline underline-offset-4"
      >
        {t("common.cancel")}
      </button>
    </>
  );
}

function SwitchLink({ onClick, children }: { onClick: () => void; children: string }) {
  return (
    <button type="button" onClick={onClick} className="self-center text-[0.8125rem] text-link hover:underline underline-offset-4">
      {children}
    </button>
  );
}

function SignedInAs({ flow }: { flow: PublicFlow }) {
  const { t } = useI18n();
  if (!flow.user) return null;
  return <p className="-mt-3 text-[0.875rem] text-muted">{t("common.signed_in_as", { username: flow.user.username })}</p>;
}

type VerifyMode = "app" | "recovery" | "passkey";

function Verify({ flow, post, passkeys }: { flow: PublicFlow; post: Post; passkeys: boolean }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const factors = flow.mfa?.factors ?? [];
  const hasApp = factors.includes("totp");
  const hasPasskey = factors.includes("webauthn") && passkeys;
  const hasRecovery = Boolean(flow.mfa?.recovery_codes);
  const [mode, setMode] = useState<VerifyMode>(hasApp ? "app" : hasPasskey ? "passkey" : "recovery");
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = mode === "recovery" ? code.trim().length >= 10 : code.length >= 6;

  const switchTo = (m: VerifyMode) => {
    setMode(m);
    setCode("");
    setError(null);
  };

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(() => post("mfa/verify", { code, remember_device: trust }));
  };
  const withPasskey = () =>
    run(async () => {
      const options = await post<PasskeyRequestOptions>("mfa/passkey/start", {});
      const credential = await assertPasskey(options);
      await post("mfa/passkey/finish", { credential, remember_device: trust });
    });

  const subtitle = mode === "recovery" ? t("mfa.recovery_description") : mode === "passkey" ? t("mfa.passkey_description") : t("mfa.description");
  const switches = (
    <>
      {mode !== "app" && hasApp && <SwitchLink onClick={() => switchTo("app")}>{t("mfa.use_app_code")}</SwitchLink>}
      {mode !== "passkey" && hasPasskey && <SwitchLink onClick={() => switchTo("passkey")}>{t("mfa.use_passkey")}</SwitchLink>}
      {mode !== "recovery" && hasRecovery && <SwitchLink onClick={() => switchTo("recovery")}>{t("mfa.use_recovery_code")}</SwitchLink>}
    </>
  );

  if (mode === "passkey") {
    return (
      <div className="flex flex-col gap-5">
        <Title sub={subtitle}>{t("mfa.title")}</Title>
        <SignedInAs flow={flow} />
        {error && <Alert tone="error">{error}</Alert>}
        <Checkbox label={t("mfa.trust_device")} checked={trust} onChange={(e) => setTrust(e.target.checked)} />
        <Button type="button" busy={busy} onClick={() => void withPasskey()}>
          {t("mfa.passkey_continue")}
        </Button>
        {switches}
        <CancelLink post={post} />
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-5">
      <Title sub={subtitle}>{t("mfa.title")}</Title>
      <SignedInAs flow={flow} />
      {error && <Alert tone="error">{error}</Alert>}
      {mode === "recovery" ? (
        <TextField
          label={t("mfa.recovery_code")}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          autoFocus
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
          placeholder="xxxxx-xxxxx"
        />
      ) : (
        <CodeInput label={t("common.code")} value={code} onChange={setCode} autoFocus />
      )}
      <Checkbox label={t("mfa.trust_device")} checked={trust} onChange={(e) => setTrust(e.target.checked)} />
      <Button type="submit" busy={busy} disabled={!ready}>
        {t("common.continue")}
      </Button>
      {switches}
      <CancelLink post={post} />
    </form>
  );
}

/** First enrolment when both an authenticator app and a passkey are on offer. */
function Choose({ flow, post, onChoose }: { flow: PublicFlow; post: Post; onChoose: (c: Choice) => void }) {
  const { t } = useI18n();
  const issuer = flow.client.name;
  const option = (choice: Choice, label: string, hint: string) => (
    <button
      type="button"
      onClick={() => onChoose(choice)}
      className="flex flex-col items-start gap-1 rounded-[var(--radius)] border border-line bg-paper px-4 py-3 text-start hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
    >
      <span className="text-[0.9375rem] font-medium text-ink">{label}</span>
      <span className="text-[0.8125rem] text-muted">{hint}</span>
    </button>
  );
  return (
    <div className="flex flex-col gap-5">
      <Title sub={t("mfa.choose_description", { issuer })}>{t("mfa.enroll_title")}</Title>
      <SignedInAs flow={flow} />
      <div className="flex flex-col gap-3">
        {option("passkey", t("mfa.choose_passkey"), t("mfa.choose_passkey_hint"))}
        {option("app", t("mfa.choose_app"), t("mfa.choose_app_hint"))}
      </div>
      <CancelLink post={post} />
    </div>
  );
}

function EnrolPasskey({ flow, post, onEnrolled, onBack }: { flow: PublicFlow; post: Post; onEnrolled: (codes: string[]) => void; onBack: () => void }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [label, setLabel] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const options = await post<PasskeyCreationOptions>("mfa/passkey/register", {});
      const credential = await createPasskey(options);
      const res = await post<MfaEnrolled | PublicFlow>("mfa/passkey/register/finish", {
        credential,
        label: label.trim() || undefined,
        remember_device: trust,
      });
      if ("recovery_codes" in res) onEnrolled(res.recovery_codes);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <Title sub={t("mfa.passkey_enroll_description")}>{t("mfa.passkey_enroll_title")}</Title>
      <SignedInAs flow={flow} />
      {error && <Alert tone="error">{error}</Alert>}
      <TextField label={t("mfa.passkey_label")} value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} autoComplete="off" autoFocus />
      <Checkbox label={t("mfa.trust_device")} checked={trust} onChange={(e) => setTrust(e.target.checked)} />
      <Button type="button" busy={busy} onClick={() => void create()}>
        {t("mfa.passkey_create")}
      </Button>
      <SwitchLink onClick={onBack}>{t("mfa.choose_other")}</SwitchLink>
      <CancelLink post={post} />
    </div>
  );
}

function Enrol({ flow, post, onEnrolled, onBack }: { flow: PublicFlow; post: Post; onEnrolled: (codes: string[]) => void; onBack: (() => void) | null }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [enrolment, setEnrolment] = useState<TotpEnrolment | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [label, setLabel] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    post<TotpEnrolment>("mfa/totp/enroll", {})
      .then(async (e) => {
        const url = await QRCode.toDataURL(e.otpauth_uri, { margin: 1, width: 192, errorCorrectionLevel: "M" });
        if (!live) return;
        setEnrolment(e);
        setQr(url);
      })
      .catch((err: unknown) => {
        if (live) setError(errorText(err));
      });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one enrolment per page load
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await post<MfaEnrolled>("mfa/totp/confirm", { code, label: label.trim() || undefined, remember_device: trust });
      onEnrolled(res.recovery_codes);
    } catch (err) {
      setError(errorText(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  const issuer = enrolment?.issuer ?? flow.client.name;
  return (
    <form onSubmit={submit} className="flex flex-col gap-5">
      <Title sub={t("mfa.enroll_description", { issuer })}>{t("mfa.enroll_title")}</Title>
      <SignedInAs flow={flow} />
      {error && <Alert tone="error">{error}</Alert>}
      {enrolment && qr ? (
        <div className="flex flex-col items-center gap-3 rounded-[var(--radius)] border border-line bg-paper p-4">
          {/* eslint-disable-next-line @next/next/no-img-element -- data URL rendered client-side */}
          <img src={qr} width={192} height={192} alt={t("mfa.qr_alt", { account: enrolment.account })} className="rounded-md bg-white" />
          <p className="text-[0.8125rem] text-muted">{t("mfa.manual_key")}</p>
          <code data-testid="totp-secret" className="max-w-full break-all rounded-md bg-ground px-2 py-1 font-mono text-[0.875rem] text-ink select-all">
            {enrolment.secret}
          </code>
        </div>
      ) : (
        <Spinner label={t("common.loading")} />
      )}
      <CodeInput label={t("common.code")} value={code} onChange={setCode} />
      <TextField label={t("mfa.app_label")} value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} autoComplete="off" />
      <Checkbox label={t("mfa.trust_device")} checked={trust} onChange={(e) => setTrust(e.target.checked)} />
      <Button type="submit" busy={busy} disabled={!enrolment || code.length < 6}>
        {t("mfa.verify_setup")}
      </Button>
      {onBack && <SwitchLink onClick={onBack}>{t("mfa.choose_other")}</SwitchLink>}
      <CancelLink post={post} />
    </form>
  );
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const text = codes.join("\n");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  const href = `data:text/plain;charset=utf-8,${encodeURIComponent(`${text}\n`)}`;
  return (
    <div className="flex flex-col gap-5">
      <Title sub={t("mfa.codes_description")}>{t("mfa.codes_title")}</Title>
      <ul aria-label={t("mfa.codes_title")} className="grid grid-cols-2 gap-x-6 gap-y-2 rounded-[var(--radius)] border border-line bg-paper p-4 font-mono text-[0.9375rem] text-ink">
        {codes.map((c) => (
          <li key={c} className="select-all">
            {c}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="secondary" className="flex-1" onClick={() => void copy()} aria-live="polite">
          {copied ? t("mfa.codes_copied") : t("mfa.codes_copy")}
        </Button>
        <a
          href={href}
          download="recovery-codes.txt"
          className="inline-flex min-h-11 flex-1 items-center justify-center rounded-[var(--radius)] border border-line px-4 text-[0.9375rem] font-medium text-ink hover:bg-ground"
        >
          {t("mfa.codes_download")}
        </a>
      </div>
      <Button type="button" onClick={onDone}>
        {t("mfa.codes_saved")}
      </Button>
    </div>
  );
}
