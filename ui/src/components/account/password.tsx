"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert, Button, Checkbox, PasswordField } from "@/components/ui";
import { Button as CButton, Card, Modal } from "@/components/console/ui";
import { needsReauth, useAccount } from "@/lib/account/session";
import { useProblemText, useSecurityChange } from "./security";

/** The password's state and the dialog that changes it. */
export function Password() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const [open, setOpen] = useState(false);
  const { reauth } = useSecurityChange();
  const status = useQuery({
    queryKey: ["account", "password", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/password", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  const s = status.data;
  if (s && !s.enabled) return null;
  const when = (iso: string | null | undefined) => (iso ? new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(new Date(iso)) : null);
  const changed = when(s?.changed_at);
  const expires = when(s?.expires_at);

  return (
    <>
      <Card
        title={t("account.password_title")}
        actions={
          <CButton variant={s?.set ? "secondary" : "primary"} onClick={() => setOpen(true)}>
            {s?.set ? t("account.password_change") : t("account.password_set")}
          </CButton>
        }
      >
        {status.isError && <Alert tone="error">{t("account.error_generic")}</Alert>}
        {s && (
          <p className="text-[0.875rem] text-muted">
            {!s.set ? t("account.password_none") : changed ? t("account.password_changed_at", { when: changed }) : t("account.password_set_hint")}
            {expires ? ` ${t("account.password_expires", { when: expires })}` : ""}
            {s.must_change ? ` ${t("account.password_must_change")}` : ""}
          </p>
        )}
      </Card>
      <Modal open={open} onOpenChange={setOpen} title={s?.set ? t("account.password_change") : t("account.password_set")}>
        {open && s && (
          <ChangePassword
            hasPassword={s.set}
            minLength={s.policy.min_length}
            onDone={() => setOpen(false)}
            onReauth={() => void reauth()}
          />
        )}
      </Modal>
    </>
  );
}

function ChangePassword({ hasPassword, minLength, onDone, onReauth }: { hasPassword: boolean; minLength: number; onDone: () => void; onReauth: () => void }) {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const qc = useQueryClient();
  const problemText = useProblemText();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [others, setOthers] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<number | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== again) {
      setError(t("account.password_mismatch"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const { data, error } = await client.PUT("/t/{slug}/account/password", {
        params: { path: { slug } },
        body: { current_password: hasPassword ? current : null, new_password: next, sign_out_others: others },
      });
      if (error) throw error;
      void qc.invalidateQueries({ queryKey: ["account", "password", slug] });
      void qc.invalidateQueries({ queryKey: ["account", "sessions", slug] });
      setDone(data.signed_out);
    } catch (err) {
      if (needsReauth(err)) onReauth();
      else setError(problemText(err));
    } finally {
      setBusy(false);
    }
  };

  if (done !== null) {
    return (
      <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
        <Alert tone="ok">{done > 0 ? t("account.password_done_signed_out", { count: done }) : t("account.password_done")}</Alert>
        <Button type="button" onClick={onDone}>
          {t("common.continue")}
        </Button>
      </div>
    );
  }
  return (
    <form onSubmit={submit} className="flex flex-col gap-4 px-5 pb-5 pt-3" noValidate>
      {error && <Alert tone="error">{error}</Alert>}
      {hasPassword && <PasswordField label={t("account.password_current")} value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" autoFocus required />}
      <PasswordField label={t("account.password_new")} value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" hint={t("account.password_min", { count: minLength })} autoFocus={!hasPassword} required />
      <PasswordField label={t("account.password_again")} value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required />
      <Checkbox label={t("account.password_sign_out_others")} checked={others} onChange={(e) => setOthers(e.target.checked)} />
      <Button type="submit" busy={busy} disabled={next.length < minLength || (hasPassword && current.length === 0)}>
        {hasPassword ? t("account.password_change") : t("account.password_set")}
      </Button>
    </form>
  );
}
