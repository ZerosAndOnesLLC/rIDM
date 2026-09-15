"use client";

import { useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { useErrorText } from "@/components/errors";
import { Alert, Button, TextField, Title } from "@/components/ui";
import { api, ApiError, tenantBase } from "@/lib/api";
import { navigate, usePageParams, WithParams } from "@/lib/params";

export default function Page() {
  return (
    <WithParams>
      <DevicePage />
    </WithParams>
  );
}

/** Device authorization (RFC 8628) user-code entry; the endpoint lands with Phase 8. */
function DevicePage() {
  const p = usePageParams();
  const { t } = useI18n();
  const errorText = useErrorText();
  const [code, setCode] = useState(p.get("user_code") ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!p.tenant) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ redirect_to?: string }>(`${tenantBase(p.tenant)}/device/verify`, { body: { user_code: code.trim().toUpperCase() } });
      if (res.redirect_to) navigate(res.redirect_to);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 404 ? t("device.unavailable") : errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <AuthShell slug={p.tenant}>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Title sub={t("device.description")}>{t("device.title")}</Title>
        {error && <Alert tone="error">{error}</Alert>}
        <TextField
          label={t("device.code")}
          value={code}
          onChange={(e) => setCode(e.target.value.toUpperCase())}
          autoComplete="off"
          autoCapitalize="characters"
          spellCheck={false}
          className="font-mono"
          autoFocus
          required
        />
        <Button type="submit" busy={busy}>
          {t("common.continue")}
        </Button>
      </form>
    </AuthShell>
  );
}
