"use client";

import { useEffect, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { CodeInput } from "@/components/code-input";
import { useErrorText } from "@/components/errors";
import { Alert, Button, Checkbox, Spinner, TextField, Title } from "@/components/ui";
import { useFlow } from "@/lib/flow";
import { usePageParams, WithParams } from "@/lib/params";
import type { PublicFlow, TotpConfirmed, TotpEnrolment } from "@/lib/types";

const ACCEPTS = ["mfa", "done"] as const;

export default function Page() {
  return (
    <WithParams>
      <MfaPage />
    </WithParams>
  );
}

/**
 * Second factor. A user with an authenticator verifies a code (or spends a
 * recovery code); one without enrols first: QR, proof code, then the
 * recovery codes shown once before the flow moves on.
 */
function MfaPage() {
  const p = usePageParams();
  const f = useFlow(p.tenant, p.flow, ACCEPTS);
  const { t } = useI18n();
  const errorText = useErrorText();
  const [codes, setCodes] = useState<string[] | null>(null);

  return (
    <AuthShell slug={p.tenant} locale={f.flow?.locale} locales={f.flow?.locales}>
      {f.loading || f.redirected || !f.flow ? (
        f.error ? <Alert tone="error">{errorText(f.error)}</Alert> : <Spinner label={t("common.loading")} />
      ) : codes ? (
        <RecoveryCodes codes={codes} onDone={() => void f.reload()} />
      ) : f.flow.mfa?.enroll ? (
        <Enrol flow={f.flow} post={f.post} onEnrolled={setCodes} />
      ) : (
        <Verify flow={f.flow} post={f.post} />
      )}
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

function Verify({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [recovery, setRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [trust, setTrust] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = recovery ? code.trim().length >= 10 : code.length >= 6;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("mfa/verify", { code, remember_device: trust });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-5">
      <Title sub={recovery ? t("mfa.recovery_description") : t("mfa.description")}>{t("mfa.title")}</Title>
      {flow.user && <p className="-mt-3 text-[0.875rem] text-muted">{t("common.signed_in_as", { username: flow.user.username })}</p>}
      {error && <Alert tone="error">{error}</Alert>}
      {recovery ? (
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
      {flow.mfa?.recovery_codes && (
        <button
          type="button"
          onClick={() => {
            setRecovery((r) => !r);
            setCode("");
            setError(null);
          }}
          className="self-center text-[0.8125rem] text-link hover:underline underline-offset-4"
        >
          {recovery ? t("mfa.use_app_code") : t("mfa.use_recovery_code")}
        </button>
      )}
      <CancelLink post={post} />
    </form>
  );
}

function Enrol({ flow, post, onEnrolled }: { flow: PublicFlow; post: Post; onEnrolled: (codes: string[]) => void }) {
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
      const res = await post<TotpConfirmed>("mfa/totp/confirm", { code, label: label.trim() || undefined, remember_device: trust });
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
      {flow.user && <p className="-mt-3 text-[0.875rem] text-muted">{t("common.signed_in_as", { username: flow.user.username })}</p>}
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
