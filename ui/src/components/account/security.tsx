"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { useCallback, useEffect, useState, useSyncExternalStore, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { RecoveryCodes } from "@/components/mfa/recovery-codes";
import { TotpSetup } from "@/components/mfa/totp-setup";
import { CodeInput } from "@/components/code-input";
import { Alert, Button, TextField } from "@/components/ui";
import { Badge, Button as CButton, Card, Modal } from "@/components/console/ui";
import { needsReauth, useAccount } from "@/lib/account/session";
import { ApiError } from "@/lib/api";
import { createPasskey, passkeysSupported } from "@/lib/passkeys";
import type { Schemas } from "@api/client";
import type { PasskeyCreationOptions, TotpEnrolment } from "@/lib/types";

type Status = Schemas["MfaStatus"];
type Factor = Status["factors"][number];
type Kind = "totp" | "webauthn" | "email_otp" | "sms_otp";

const noop = () => () => {};

/**
 * Security changes need a recent sign-in, with the second step once the
 * account has one; the API says so with a problem the page answers by
 * sending the user through sign-in and back here.
 */
export function useSecurityChange() {
  const { reauth, client, slug } = useAccount();
  const status = useQuery({
    queryKey: ["account", "mfa", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/mfa", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  const hasFactor = (status.data?.factors.length ?? 0) > 0;
  return { status, reauth: useCallback(() => reauth(hasFactor), [reauth, hasFactor]) };
}

/** Text for an API refusal: field errors first, then the problem's own words. */
export function useProblemText() {
  const { t } = useI18n();
  return (e: unknown): string => {
    const p = e as { detail?: string; errors?: { field: string; message: string }[] } | null;
    const first = p?.errors?.[0];
    if (first) return `${first.field === "code" ? t("common.code") : first.field} ${first.message}`;
    if (e instanceof ApiError) return e.message;
    return p?.detail ?? t("account.error_generic");
  };
}

export function Security() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const { status, reauth } = useSecurityChange();
  const supported = useSyncExternalStore(noop, passkeysSupported, () => false);
  const problemText = useProblemText();
  const [adding, setAdding] = useState<Kind | null>(null);
  const [removing, setRemoving] = useState<Factor | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirmCodes, setConfirmCodes] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => void qc.invalidateQueries({ queryKey: ["account", "mfa", slug] });
  const fail = (e: unknown) => {
    if (needsReauth(e)) void reauth();
    else setError(problemText(e));
  };
  const enrolled = (recovery: string[] | null | undefined) => {
    setAdding(null);
    refresh();
    if (recovery) setCodes(recovery);
  };

  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/t/{slug}/account/mfa/credentials/{credential_id}", { params: { path: { slug, credential_id: id } } });
      if (error) throw error;
    },
    onSuccess: () => {
      setRemoving(null);
      refresh();
    },
    onError: (e: unknown) => {
      setRemoving(null);
      fail(e);
    },
  });
  const renew = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/t/{slug}/account/mfa/recovery-codes", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
    onSuccess: (d) => {
      setConfirmCodes(false);
      refresh();
      setCodes(d.recovery_codes);
    },
    onError: (e: unknown) => {
      setConfirmCodes(false);
      fail(e);
    },
  });

  const s = status.data;
  const factors = s?.factors ?? [];
  const has = (k: Kind) => factors.some((f) => f.kind === k);
  const offered: Kind[] = (s?.methods ?? []).filter((m): m is Kind => (m === "webauthn" ? supported : !has(m as Kind)));
  const when = (iso: string | null | undefined) => (iso ? new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(new Date(iso)) : null);
  const kindName = (k: string) => t(`account.kind.${k}`);

  return (
    <>
      <Card title={t("account.mfa_title")}>
        <p className="text-[0.875rem] text-muted">{s?.policy === "required" ? t("account.mfa_required_hint") : t("account.mfa_description")}</p>
        {error && (
          <div className="mt-3">
            <Alert tone="error">{error}</Alert>
          </div>
        )}
        {status.isError && (
          <div className="mt-3">
            <Alert tone="error">{t("account.error_generic")}</Alert>
          </div>
        )}
        {s && factors.length === 0 && <p className="mt-3 text-[0.875rem] text-ink">{t("account.mfa_none")}</p>}
        {factors.length > 0 && (
          <ul aria-label={t("account.mfa_title")} className="mt-3 divide-y divide-line">
            {factors.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <p className="flex items-center gap-2 text-[0.9375rem] font-medium text-ink">
                    <span>{kindName(f.kind)}</span>
                    {f.label && f.label !== kindName(f.kind) && <Badge>{f.label}</Badge>}
                  </p>
                  <p className="text-[0.8125rem] text-muted">
                    {t("account.factor_added", { when: when(f.created_at) ?? "" })}
                    {f.last_used_at ? ` · ${t("account.factor_used", { when: when(f.last_used_at) ?? "" })}` : ""}
                  </p>
                </div>
                <CButton variant="secondary" onClick={() => setRemoving(f)}>
                  {t("account.remove")}
                </CButton>
              </li>
            ))}
          </ul>
        )}
        {offered.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {offered.map((k) => (
              <CButton key={k} variant={factors.length === 0 ? "primary" : "secondary"} onClick={() => setAdding(k)}>
                {t(`account.add.${k}`)}
              </CButton>
            ))}
          </div>
        )}
      </Card>

      {factors.length > 0 && (
        <Card
          title={t("account.codes_title")}
          actions={
            <CButton variant="secondary" onClick={() => setConfirmCodes(true)}>
              {t("account.codes_renew")}
            </CButton>
          }
        >
          <p className="text-[0.875rem] text-muted">{t("account.codes_description")}</p>
          <p className="mt-2 text-[0.9375rem] text-ink">{t("account.codes_left", { count: s?.recovery_codes ?? 0 })}</p>
        </Card>
      )}

      <Modal open={adding === "totp"} onOpenChange={(o) => !o && setAdding(null)} title={t("account.add.totp")}>
        {adding === "totp" && <AddApp onDone={enrolled} onError={fail} />}
      </Modal>
      <Modal open={adding === "webauthn"} onOpenChange={(o) => !o && setAdding(null)} title={t("account.add.webauthn")}>
        {adding === "webauthn" && <AddPasskey onDone={enrolled} onError={fail} />}
      </Modal>
      <Modal open={adding === "email_otp" || adding === "sms_otp"} onOpenChange={(o) => !o && setAdding(null)} title={adding === "sms_otp" ? t("account.add.sms_otp") : t("account.add.email_otp")}>
        {(adding === "email_otp" || adding === "sms_otp") && <AddOtp channel={adding === "sms_otp" ? "sms" : "email"} phone={s?.phone ?? null} onDone={enrolled} onError={fail} />}
      </Modal>

      <Modal open={removing !== null} onOpenChange={(o) => !o && setRemoving(null)} title={t("account.remove_title", { kind: removing ? kindName(removing.kind) : "" })}>
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <p className="text-[0.9375rem] text-ink">{factors.length === 1 ? t("account.remove_last_hint") : t("account.remove_hint")}</p>
          <div className="flex justify-end gap-2">
            <CButton variant="secondary" onClick={() => setRemoving(null)}>
              {t("common.cancel")}
            </CButton>
            <CButton variant="danger" onClick={() => removing && remove.mutate(removing.id)} disabled={remove.isPending}>
              {t("account.remove")}
            </CButton>
          </div>
        </div>
      </Modal>

      <Modal open={confirmCodes} onOpenChange={setConfirmCodes} title={t("account.codes_renew")}>
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <p className="text-[0.9375rem] text-ink">{t("account.codes_renew_hint")}</p>
          <div className="flex justify-end gap-2">
            <CButton variant="secondary" onClick={() => setConfirmCodes(false)}>
              {t("common.cancel")}
            </CButton>
            <CButton variant="primary" onClick={() => renew.mutate()} disabled={renew.isPending}>
              {t("account.codes_renew")}
            </CButton>
          </div>
        </div>
      </Modal>

      <Modal open={codes !== null} onOpenChange={(o) => !o && setCodes(null)} title={t("account.codes_title")} hideTitle>
        <div className="overflow-y-auto px-5 pb-5 pt-4">{codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}</div>
      </Modal>
    </>
  );
}

type Done = (recovery: string[] | null | undefined) => void;

function useBusy(onError: (e: unknown) => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problemText = useProblemText();
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      if (needsReauth(e)) onError(e);
      else setError(problemText(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run };
}

function AddApp({ onDone, onError }: { onDone: Done; onError: (e: unknown) => void }) {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const [enrolment, setEnrolment] = useState<TotpEnrolment | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [label, setLabel] = useState("");
  const { busy, error, run } = useBusy(onError);
  const [startError, setStartError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    client
      .POST("/t/{slug}/account/mfa/totp/enroll", { params: { path: { slug } } })
      .then(async ({ data, error }) => {
        if (error) throw error;
        const url = await QRCode.toDataURL(data.otpauth_uri, { margin: 1, width: 192, errorCorrectionLevel: "M" });
        if (!live) return;
        setEnrolment(data);
        setQr(url);
      })
      .catch((e: unknown) => {
        if (!live) return;
        if (needsReauth(e)) onError(e);
        else setStartError((e as { detail?: string })?.detail ?? t("account.error_generic"));
      });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one enrolment per dialog
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const { data, error } = await client.POST("/t/{slug}/account/mfa/totp/confirm", { params: { path: { slug } }, body: { code, label: label.trim() || null } });
      if (error) throw error;
      onDone(data.recovery_codes);
    }).then(() => setCode(""));
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-4 overflow-y-auto px-5 pb-5 pt-3">
      <p className="text-[0.875rem] text-muted">{t("account.app_hint")}</p>
      {(error ?? startError) && <Alert tone="error">{error ?? startError}</Alert>}
      <TotpSetup enrolment={enrolment} qr={qr} />
      <CodeInput label={t("common.code")} value={code} onChange={setCode} />
      <TextField label={t("mfa.app_label")} value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} autoComplete="off" />
      <Button type="submit" busy={busy} disabled={!enrolment || code.length < 6}>
        {t("mfa.verify_setup")}
      </Button>
    </form>
  );
}

function AddPasskey({ onDone, onError }: { onDone: Done; onError: (e: unknown) => void }) {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const [label, setLabel] = useState("");
  const { busy, error, run } = useBusy(onError);

  const create = () =>
    run(async () => {
      const start = await client.POST("/t/{slug}/account/mfa/passkey/register", { params: { path: { slug } } });
      if (start.error) throw start.error;
      const credential = await createPasskey(start.data as PasskeyCreationOptions);
      const finish = await client.POST("/t/{slug}/account/mfa/passkey/register/finish", {
        params: { path: { slug } },
        body: { credential: credential as unknown as Record<string, never>, label: label.trim() || null },
      });
      if (finish.error) throw finish.error;
      onDone(finish.data.recovery_codes);
    });

  return (
    <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
      <p className="text-[0.875rem] text-muted">{t("mfa.passkey_enroll_description")}</p>
      {error && <Alert tone="error">{error}</Alert>}
      <TextField label={t("mfa.passkey_label")} value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} autoComplete="off" autoFocus />
      <Button type="button" busy={busy} onClick={() => void create()}>
        {t("mfa.passkey_create")}
      </Button>
    </div>
  );
}

function AddOtp({ channel, phone, onDone, onError }: { channel: "email" | "sms"; phone: string | null; onDone: Done; onError: (e: unknown) => void }) {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const needsPhone = channel === "sms" && !phone;
  const [number, setNumber] = useState("");
  const [sent, setSent] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const { busy, error, run } = useBusy(onError);

  const send = (n?: string) =>
    run(async () => {
      const res =
        channel === "email"
          ? await client.POST("/t/{slug}/account/mfa/email/enroll", { params: { path: { slug } } })
          : await client.POST("/t/{slug}/account/mfa/sms/enroll", { params: { path: { slug } }, body: { phone: n ?? null } });
      if (res.error) throw res.error;
      setSent(res.data.destination);
    });

  useEffect(() => {
    if (!needsPhone) void send();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one code per dialog
  }, []);

  const confirm = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const res =
        channel === "email"
          ? await client.POST("/t/{slug}/account/mfa/email/confirm", { params: { path: { slug } }, body: { code, label: null } })
          : await client.POST("/t/{slug}/account/mfa/sms/confirm", { params: { path: { slug } }, body: { code, label: null } });
      if (res.error) throw res.error;
      onDone(res.data.recovery_codes);
    }).then(() => setCode(""));
  };

  if (!sent) {
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void send(number);
        }}
        className="flex flex-col gap-4 px-5 pb-5 pt-3"
      >
        <p className="text-[0.875rem] text-muted">{needsPhone ? t("mfa.sms_enroll_description") : t("mfa.sending")}</p>
        {error && <Alert tone="error">{error}</Alert>}
        {needsPhone && (
          <>
            <TextField label={t("common.phone")} type="tel" value={number} onChange={(e) => setNumber(e.target.value)} autoComplete="tel" inputMode="tel" placeholder="+15551234567" autoFocus />
            <Button type="submit" busy={busy} disabled={number.trim().length < 7}>
              {t("mfa.send_code")}
            </Button>
          </>
        )}
      </form>
    );
  }
  return (
    <form onSubmit={confirm} className="flex flex-col gap-4 px-5 pb-5 pt-3">
      <p className="text-[0.875rem] text-muted">{t("login.code_sent", { destination: sent, minutes: 10 })}</p>
      {error && <Alert tone="error">{error}</Alert>}
      <CodeInput label={t("common.code")} value={code} onChange={setCode} autoFocus />
      <Button type="submit" busy={busy} disabled={code.length < 6}>
        {t("mfa.verify_setup")}
      </Button>
      <button type="button" onClick={() => void send(needsPhone ? number : undefined)} className="self-center text-[0.8125rem] text-link hover:underline underline-offset-4">
        {t("login.resend")}
      </button>
    </form>
  );
}
