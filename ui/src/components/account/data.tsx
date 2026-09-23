"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert, Button, TextField } from "@/components/ui";
import { Button as CButton, Card, Modal } from "@/components/console/ui";
import { accountStore, needsReauth, useAccount } from "@/lib/account/session";
import { API_BASE } from "@/lib/api";
import { saveResponse } from "@/lib/download";
import { useProblemText, useSecurityChange } from "./security";

/** Everything held about the user, as one JSON file. */
export function Export() {
  const { slug } = useAccount();
  const { t } = useI18n();
  const { reauth } = useSecurityChange();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const download = async () => {
    setBusy(true);
    setError(null);
    try {
      const token = await accountStore.token();
      const res = await fetch(`${API_BASE}/t/${encodeURIComponent(slug)}/account/export`, { headers: { Authorization: `Bearer ${token ?? ""}` } });
      if (!res.ok) {
        const problem: unknown = await res.json().catch(() => null);
        if (needsReauth(problem)) {
          void reauth();
          return;
        }
        throw new Error((problem as { detail?: string } | null)?.detail ?? t("account.error_generic"));
      }
      await saveResponse(res, `${slug}-account.json`);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("account.error_generic"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title={t("account.export_title")}
      actions={
        <CButton variant="secondary" onClick={() => void download()} disabled={busy}>
          {t("account.export_download")}
        </CButton>
      }
    >
      <p className="text-[0.875rem] text-muted">{t("account.export_description")}</p>
      {error && (
        <div className="mt-3">
          <Alert tone="error">{error}</Alert>
        </div>
      )}
    </Card>
  );
}

/** Leaving: the username typed again, then everything ends. */
export function DeleteAccount() {
  const { client, slug, me } = useAccount();
  const { t } = useI18n();
  const router = useRouter();
  const { reauth } = useSecurityChange();
  const problemText = useProblemText();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { error } = await client.DELETE("/t/{slug}/account/me", { params: { path: { slug } }, body: { confirm } });
      if (error) throw error;
      accountStore.end(t("account.delete_done"));
      router.push("/account/");
    } catch (err) {
      if (needsReauth(err)) void reauth();
      else setError(problemText(err));
      setBusy(false);
    }
  };

  return (
    <>
      <Card
        title={t("account.delete_title")}
        actions={
          <CButton variant="danger" onClick={() => setOpen(true)}>
            {t("account.delete_button")}
          </CButton>
        }
      >
        <p className="text-[0.875rem] text-muted">{t("account.delete_description")}</p>
      </Card>
      <Modal open={open} onOpenChange={setOpen} title={t("account.delete_title")}>
        <form onSubmit={submit} className="flex flex-col gap-4 px-5 pb-5 pt-3" noValidate>
          <p className="text-[0.9375rem] text-ink">{t("account.delete_hint")}</p>
          {error && <Alert tone="error">{error}</Alert>}
          <TextField label={t("account.delete_confirm", { username: me?.username ?? "" })} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} autoFocus required />
          <Button type="submit" variant="danger" busy={busy} disabled={confirm.trim().toLowerCase() !== (me?.username ?? "")}>
            {t("account.delete_button")}
          </Button>
        </form>
      </Modal>
    </>
  );
}
