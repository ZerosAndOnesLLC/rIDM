"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { CodeInput } from "@/components/code-input";
import { Alert, Button, TextField } from "@/components/ui";
import { Badge, Button as CButton, Card, Modal } from "@/components/console/ui";
import { needsReauth, refreshMe, useAccount } from "@/lib/account/session";
import { useProfile } from "./profile";
import { useProblemText, useSecurityChange } from "./security";

type Channel = "email" | "phone";

/** The address and number on the account, each changed by proving the new one with a code. */
export function Contact() {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const qc = useQueryClient();
  const profile = useProfile();
  const { reauth } = useSecurityChange();
  const problemText = useProblemText();
  const [changing, setChanging] = useState<Channel | null>(null);
  const [removing, setRemoving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["account", "profile", slug] });
    void refreshMe();
  };
  const fail = (e: unknown) => {
    if (needsReauth(e)) void reauth();
    else setError(problemText(e));
  };
  const cancel = useMutation({
    mutationFn: async (channel: Channel) => {
      const { error } = channel === "email" ? await client.DELETE("/t/{slug}/account/email/change", { params: { path: { slug } } }) : await client.DELETE("/t/{slug}/account/phone/change", { params: { path: { slug } } });
      if (error) throw error;
    },
    onSuccess: refresh,
    onError: fail,
  });
  const removePhone = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/t/{slug}/account/phone", { params: { path: { slug } } });
      if (error) throw error;
    },
    onSuccess: () => {
      setRemoving(false);
      refresh();
    },
    onError: (e: unknown) => {
      setRemoving(false);
      fail(e);
    },
  });

  const p = profile.data;
  const row = (channel: Channel) => {
    const value = channel === "email" ? p?.email : p?.phone;
    const verified = channel === "email" ? p?.email_verified : p?.phone_verified;
    const pending = channel === "email" ? p?.pending.email : p?.pending.phone;
    return (
      <li className="flex flex-wrap items-center justify-between gap-3 py-3">
        <div className="min-w-0">
          <p className="text-[0.8125rem] text-muted">{channel === "email" ? t("common.email") : t("common.phone")}</p>
          <p className="flex flex-wrap items-center gap-2 text-[0.9375rem] font-medium text-ink">
            <span className="truncate">{value ?? t("account.contact_none")}</span>
            {value && <Badge tone={verified ? "ok" : "neutral"}>{verified ? t("account.verified") : t("account.unverified")}</Badge>}
          </p>
          {pending && (
            <p className="mt-1 text-[0.8125rem] text-muted">
              {t("account.contact_pending", { destination: pending })}{" "}
              <button type="button" onClick={() => setChanging(channel)} className="text-link hover:underline underline-offset-4">
                {t("account.contact_enter_code")}
              </button>
              {" · "}
              <button type="button" onClick={() => cancel.mutate(channel)} className="text-link hover:underline underline-offset-4">
                {t("common.cancel")}
              </button>
            </p>
          )}
        </div>
        <div className="flex gap-2">
          {channel === "phone" && value && (
            <CButton variant="secondary" onClick={() => setRemoving(true)}>
              {t("account.remove")}
            </CButton>
          )}
          <CButton variant="secondary" onClick={() => setChanging(channel)}>
            {value ? t("account.contact_change") : t("account.contact_add")}
          </CButton>
        </div>
      </li>
    );
  };

  return (
    <>
      <Card title={t("account.contact_title")}>
        <p className="text-[0.875rem] text-muted">{t("account.contact_description")}</p>
        {error && (
          <div className="mt-3">
            <Alert tone="error">{error}</Alert>
          </div>
        )}
        {p && (
          <ul className="mt-2 divide-y divide-line">
            {row("email")}
            {row("phone")}
          </ul>
        )}
      </Card>

      <Modal open={changing !== null} onOpenChange={(o) => !o && setChanging(null)} title={changing === "phone" ? t("account.change_phone") : t("account.change_email")}>
        {changing && (
          <ChangeContact
            channel={changing}
            pending={(changing === "email" ? p?.pending.email : p?.pending.phone) ?? null}
            onDone={() => {
              setChanging(null);
              refresh();
            }}
            onReauth={() => void reauth()}
          />
        )}
      </Modal>

      <Modal open={removing} onOpenChange={setRemoving} title={t("account.remove_phone_title")}>
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <p className="text-[0.9375rem] text-ink">{t("account.remove_phone_hint")}</p>
          <div className="flex justify-end gap-2">
            <CButton variant="secondary" onClick={() => setRemoving(false)}>
              {t("common.cancel")}
            </CButton>
            <CButton variant="danger" onClick={() => removePhone.mutate()} disabled={removePhone.isPending}>
              {t("account.remove")}
            </CButton>
          </div>
        </div>
      </Modal>
    </>
  );
}

/** Two steps: the new destination (a code goes there), then the code. */
function ChangeContact({ channel, pending, onDone, onReauth }: { channel: Channel; pending: string | null; onDone: () => void; onReauth: () => void }) {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const problemText = useProblemText();
  const [value, setValue] = useState("");
  const [sent, setSent] = useState<string | null>(pending);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      if (needsReauth(e)) onReauth();
      else setError(problemText(e));
    } finally {
      setBusy(false);
    }
  };

  const send = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const res =
        channel === "email"
          ? await client.POST("/t/{slug}/account/email/change", { params: { path: { slug } }, body: { email: value } })
          : await client.POST("/t/{slug}/account/phone/change", { params: { path: { slug } }, body: { phone: value } });
      if (res.error) throw res.error;
      setSent(res.data.destination);
    });
  };
  const confirm = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const res =
        channel === "email"
          ? await client.POST("/t/{slug}/account/email/confirm", { params: { path: { slug } }, body: { code } })
          : await client.POST("/t/{slug}/account/phone/confirm", { params: { path: { slug } }, body: { code } });
      if (res.error) throw res.error;
      onDone();
    });
  };

  if (!sent) {
    return (
      <form onSubmit={send} className="flex flex-col gap-4 px-5 pb-5 pt-3" noValidate>
        <p className="text-[0.875rem] text-muted">{channel === "email" ? t("account.change_email_hint") : t("account.change_phone_hint")}</p>
        {error && <Alert tone="error">{error}</Alert>}
        {channel === "email" ? (
          <TextField label={t("account.new_email")} type="email" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="email" inputMode="email" autoFocus required />
        ) : (
          <TextField label={t("account.new_phone")} type="tel" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="tel" inputMode="tel" placeholder="+15551234567" autoFocus required />
        )}
        <Button type="submit" busy={busy} disabled={value.trim().length < 3}>
          {t("mfa.send_code")}
        </Button>
      </form>
    );
  }
  return (
    <form onSubmit={confirm} className="flex flex-col gap-4 px-5 pb-5 pt-3">
      <p className="text-[0.875rem] text-muted">{t("login.code_sent", { destination: sent, minutes: 10 })}</p>
      {error && <Alert tone="error">{error}</Alert>}
      <CodeInput label={t("common.code")} value={code} onChange={setCode} autoFocus />
      <Button type="submit" busy={busy} disabled={code.length < 6}>
        {t("account.contact_confirm")}
      </Button>
      <button type="button" onClick={() => setSent(null)} className="self-center text-[0.8125rem] text-link hover:underline underline-offset-4">
        {t("account.contact_other")}
      </button>
    </form>
  );
}
