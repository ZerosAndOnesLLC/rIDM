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
import { RecoveryCodes } from "@/components/mfa/recovery-codes";
import { TotpSetup } from "@/components/mfa/totp-setup";
import type { Factor, MfaEnrolled, OtpSent, PasskeyCreationOptions, PasskeyRequestOptions, PublicFlow, TotpEnrolment } from "@/lib/types";

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

type Choice = "app" | "passkey" | "email" | "sms";
type OtpChannel = "email" | "sms";

/** The enrolment choices the tenant offers this user, in display order. */
function choicesOf(methods: Factor[], passkeys: boolean): Choice[] {
  const out: Choice[] = [];
  if (methods.includes("webauthn") && passkeys) out.push("passkey");
  if (methods.includes("totp")) out.push("app");
  if (methods.includes("email_otp")) out.push("email");
  if (methods.includes("sms_otp")) out.push("sms");
  return out;
}

/**
 * Second factor. A user with a factor verifies with it (an authenticator
 * code, a passkey, a code by email or text message, or a recovery code);
 * one without enrols first, choosing between the methods the tenant offers
 * when there is more than one, then sees the recovery codes once before the
 * flow moves on.
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
    const choices = choicesOf(f.flow.mfa.methods, supported);
    const chosen = choices.length === 1 ? choices[0] : choice;
    const back = choices.length > 1 ? () => setChoice(null) : null;
    if (chosen === "passkey") {
      body = <EnrolPasskey flow={f.flow} post={f.post} onEnrolled={setCodes} onBack={back} />;
    } else if (chosen === "app") {
      body = <Enrol flow={f.flow} post={f.post} onEnrolled={setCodes} onBack={back} />;
    } else if (chosen === "email" || chosen === "sms") {
      body = <EnrolOtp key={chosen} channel={chosen} flow={f.flow} post={f.post} onEnrolled={setCodes} onBack={back} />;
    } else if (choices.length === 0) {
      body = (
        <div className="flex flex-col gap-5">
          <Title>{t("mfa.enroll_title")}</Title>
          <Alert tone="error">{t("mfa.no_methods")}</Alert>
          <CancelLink post={f.post} />
        </div>
      );
    } else {
      body = <Choose flow={f.flow} post={f.post} choices={choices} onChoose={setChoice} />;
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

type VerifyMode = "app" | "recovery" | "passkey" | OtpChannel;

/**
 * Asks the API for a code over `channel` whenever the mode is one; the API
 * reuses a code it sent moments ago, so a re-run sends nothing twice.
 */
function useSendCode(post: Post, channel: OtpChannel | null, resend: number) {
  const errorText = useErrorText();
  const [sent, setSent] = useState<{ channel: OtpChannel; destination: string } | null>(null);
  const [error, setError] = useState<{ channel: OtpChannel; text: string | null } | null>(null);
  useEffect(() => {
    if (!channel) return;
    let live = true;
    post<OtpSent>(`mfa/${channel}/send`, {})
      .then((s) => {
        if (!live) return;
        setSent({ channel, destination: s.destination });
        setError(null);
      })
      .catch((err: unknown) => {
        if (live) setError({ channel, text: errorText(err) });
      });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one send per channel choice or explicit resend
  }, [channel, resend]);
  return { sent: sent?.channel === channel ? sent : null, error: error?.channel === channel ? error.text : null };
}

function Verify({ flow, post, passkeys }: { flow: PublicFlow; post: Post; passkeys: boolean }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const factors = flow.mfa?.factors ?? [];
  const hasApp = factors.includes("totp");
  const hasPasskey = factors.includes("webauthn") && passkeys;
  const hasEmail = factors.includes("email_otp");
  const hasSms = factors.includes("sms_otp");
  const hasRecovery = Boolean(flow.mfa?.recovery_codes);
  const [mode, setMode] = useState<VerifyMode>(hasApp ? "app" : hasPasskey ? "passkey" : hasEmail ? "email" : hasSms ? "sms" : "recovery");
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resend, setResend] = useState(0);
  const otp = mode === "email" || mode === "sms" ? mode : null;
  const delivery = useSendCode(post, otp, resend);
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
    void run(() => post(otp ? `mfa/${otp}/verify` : "mfa/verify", { code, remember_device: trust }));
  };
  const withPasskey = () =>
    run(async () => {
      const options = await post<PasskeyRequestOptions>("mfa/passkey/start", {});
      const credential = await assertPasskey(options);
      await post("mfa/passkey/finish", { credential, remember_device: trust });
    });

  let subtitle: string;
  if (mode === "recovery") subtitle = t("mfa.recovery_description");
  else if (mode === "passkey") subtitle = t("mfa.passkey_description");
  else if (otp) subtitle = delivery.sent ? t("login.code_sent", { destination: delivery.sent.destination, minutes: 10 }) : t("mfa.sending");
  else subtitle = t("mfa.description");
  const switches = (
    <>
      {mode !== "app" && hasApp && <SwitchLink onClick={() => switchTo("app")}>{t("mfa.use_app_code")}</SwitchLink>}
      {mode !== "passkey" && hasPasskey && <SwitchLink onClick={() => switchTo("passkey")}>{t("mfa.use_passkey")}</SwitchLink>}
      {mode !== "email" && hasEmail && <SwitchLink onClick={() => switchTo("email")}>{t("mfa.use_email")}</SwitchLink>}
      {mode !== "sms" && hasSms && <SwitchLink onClick={() => switchTo("sms")}>{t("mfa.use_sms")}</SwitchLink>}
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
      {(error ?? delivery.error) && <Alert tone="error">{error ?? delivery.error}</Alert>}
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
      <Button type="submit" busy={busy} disabled={!ready || (otp !== null && !delivery.sent)}>
        {t("common.continue")}
      </Button>
      {otp && <SwitchLink onClick={() => setResend((n) => n + 1)}>{t("login.resend")}</SwitchLink>}
      {switches}
      <CancelLink post={post} />
    </form>
  );
}

const CHOICE_TEXT: Record<Choice, { label: string; hint: string }> = {
  passkey: { label: "mfa.choose_passkey", hint: "mfa.choose_passkey_hint" },
  app: { label: "mfa.choose_app", hint: "mfa.choose_app_hint" },
  email: { label: "mfa.choose_email", hint: "mfa.choose_email_hint" },
  sms: { label: "mfa.choose_sms", hint: "mfa.choose_sms_hint" },
};

/** First enrolment when the tenant offers more than one method. */
function Choose({ flow, post, choices, onChoose }: { flow: PublicFlow; post: Post; choices: Choice[]; onChoose: (c: Choice) => void }) {
  const { t } = useI18n();
  const issuer = flow.client.name;
  return (
    <div className="flex flex-col gap-5">
      <Title sub={t("mfa.choose_description", { issuer })}>{t("mfa.enroll_title")}</Title>
      <SignedInAs flow={flow} />
      <div className="flex flex-col gap-3">
        {choices.map((choice) => (
          <button
            key={choice}
            type="button"
            onClick={() => onChoose(choice)}
            className="flex flex-col items-start gap-1 rounded-[var(--radius)] border border-line bg-paper px-4 py-3 text-start hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          >
            <span className="text-[0.9375rem] font-medium text-ink">{t(CHOICE_TEXT[choice].label)}</span>
            <span className="text-[0.8125rem] text-muted">{t(CHOICE_TEXT[choice].hint)}</span>
          </button>
        ))}
      </div>
      <CancelLink post={post} />
    </div>
  );
}

/**
 * Enrol a code by email or text message: the code goes out at once (an SMS
 * enrolment first asks for a number when the account has none), and the
 * right code makes the channel the user's second factor.
 */
function EnrolOtp({ channel, flow, post, onEnrolled, onBack }: { channel: OtpChannel; flow: PublicFlow; post: Post; onEnrolled: (codes: string[]) => void; onBack: (() => void) | null }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const needsPhone = channel === "sms" && !flow.mfa?.phone;
  const [phone, setPhone] = useState("");
  const [sent, setSent] = useState<OtpSent | null>(null);
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
  const send = (number?: string) => run(async () => setSent(await post<OtpSent>(`mfa/${channel}/enroll`, number ? { phone: number } : {})));

  useEffect(() => {
    if (needsPhone) return;
    let live = true;
    post<OtpSent>(`mfa/${channel}/enroll`, {})
      .then((s) => {
        if (live) setSent(s);
      })
      .catch((err: unknown) => {
        if (live) setError(errorText(err));
      });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one code per enrolment screen
  }, []);

  const confirm = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await post<MfaEnrolled | PublicFlow>(`mfa/${channel}/confirm`, { code, remember_device: trust });
      if ("recovery_codes" in res) onEnrolled(res.recovery_codes);
    } catch (err) {
      setError(errorText(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  const title = channel === "email" ? t("mfa.email_enroll_title") : t("mfa.sms_enroll_title");
  if (!sent) {
    if (needsPhone) {
      return (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send(phone);
          }}
          className="flex flex-col gap-5"
        >
          <Title sub={t("mfa.sms_enroll_description")}>{title}</Title>
          <SignedInAs flow={flow} />
          {error && <Alert tone="error">{error}</Alert>}
          <TextField label={t("common.phone")} type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} autoComplete="tel" inputMode="tel" placeholder="+15551234567" autoFocus />
          <Button type="submit" busy={busy} disabled={phone.trim().length < 7}>
            {t("mfa.send_code")}
          </Button>
          {onBack && <SwitchLink onClick={onBack}>{t("mfa.choose_other")}</SwitchLink>}
          <CancelLink post={post} />
        </form>
      );
    }
    return (
      <div className="flex flex-col gap-5">
        <Title sub={t("mfa.sending")}>{title}</Title>
        <SignedInAs flow={flow} />
        {error ? <Alert tone="error">{error}</Alert> : <Spinner label={t("common.loading")} />}
        {onBack && <SwitchLink onClick={onBack}>{t("mfa.choose_other")}</SwitchLink>}
        <CancelLink post={post} />
      </div>
    );
  }

  return (
    <form onSubmit={confirm} className="flex flex-col gap-5">
      <Title sub={t("login.code_sent", { destination: sent.destination, minutes: 10 })}>{title}</Title>
      <SignedInAs flow={flow} />
      {error && <Alert tone="error">{error}</Alert>}
      <CodeInput label={t("common.code")} value={code} onChange={setCode} autoFocus />
      <Checkbox label={t("mfa.trust_device")} checked={trust} onChange={(e) => setTrust(e.target.checked)} />
      <Button type="submit" busy={busy} disabled={code.length < 6}>
        {t("mfa.verify_setup")}
      </Button>
      <SwitchLink onClick={() => void send(needsPhone ? phone : undefined)}>{t("login.resend")}</SwitchLink>
      {onBack && <SwitchLink onClick={onBack}>{t("mfa.choose_other")}</SwitchLink>}
      <CancelLink post={post} />
    </form>
  );
}

function EnrolPasskey({ flow, post, onEnrolled, onBack }: { flow: PublicFlow; post: Post; onEnrolled: (codes: string[]) => void; onBack: (() => void) | null }) {
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
      {onBack && <SwitchLink onClick={onBack}>{t("mfa.choose_other")}</SwitchLink>}
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
      <TotpSetup enrolment={enrolment} qr={qr} />
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
