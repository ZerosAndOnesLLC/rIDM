"use client";

import { useEffect, useState } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { useErrorText } from "@/components/errors";
import { Alert, Button, Spinner, Title } from "@/components/ui";
import { api, ApiError, tenantBase } from "@/lib/api";
import { navigate, usePageParams, WithParams } from "@/lib/params";
import type { LogoutView } from "@/lib/types";

export default function Page() {
  return (
    <WithParams>
      <LogoutPage />
    </WithParams>
  );
}

interface Confirmed {
  redirect_to: string;
  logged_out: boolean;
  frontchannel_logout_uris?: string[];
}

function LogoutPage() {
  const p = usePageParams();
  const { t } = useI18n();
  const errorText = useErrorText();
  const [view, setView] = useState<LogoutView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const [busy, setBusy] = useState<"yes" | "no" | null>(null);
  const [frames, setFrames] = useState<string[]>([]);
  const done = p.get("done") === "1";
  const cancelled = p.get("cancelled") === "1";

  useEffect(() => {
    if (!p.tenant || !p.flow || done || cancelled) return;
    const ctrl = new AbortController();
    api<LogoutView>(`${tenantBase(p.tenant)}/end_session/${encodeURIComponent(p.flow)}`, { signal: ctrl.signal })
      .then(setView)
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        if (e instanceof ApiError && e.status === 404) setExpired(true);
        else setError(errorText(e));
      });
    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- errorText is stable per locale
  }, [p.tenant, p.flow, done, cancelled]);

  const decide = async (confirm: boolean) => {
    if (!p.tenant || !view) return;
    setBusy(confirm ? "yes" : "no");
    setError(null);
    try {
      const res = await api<Confirmed>(`${tenantBase(p.tenant)}/end_session/confirm`, {
        body: { flow: view.id, csrf: view.csrf, confirm },
      });
      const uris = res.frontchannel_logout_uris ?? [];
      if (uris.length === 0) return navigate(res.redirect_to);
      // Let the relying parties clear their sessions before leaving.
      setFrames(uris);
      window.setTimeout(() => navigate(res.redirect_to), 1500);
    } catch (e) {
      setError(errorText(e));
      setBusy(null);
    }
  };

  return (
    <AuthShell slug={p.tenant} locale={view?.locale}>
      {done ? (
        <>
          <Title>{t("logout.title")}</Title>
          <Alert tone="ok">{t("logout.done")}</Alert>
        </>
      ) : cancelled ? (
        <>
          <Title>{t("logout.title")}</Title>
          <Alert tone="info">{t("logout.cancelled")}</Alert>
        </>
      ) : expired ? (
        <Alert tone="error">{t("common.expired")}</Alert>
      ) : frames.length > 0 ? (
        <>
          <Spinner label={t("logout.frontchannel")} />
          {frames.map((u) => (
            <iframe key={u} src={u} title="logout" hidden />
          ))}
        </>
      ) : !view ? (
        error ? <Alert tone="error">{error}</Alert> : <Spinner label={t("common.loading")} />
      ) : (
        <div className="flex flex-col gap-5">
          <Title>{view.client ? t("logout.confirm", { client: view.client.name }) : t("logout.sign_out")}</Title>
          {error && <Alert tone="error">{error}</Alert>}
          {!view.signed_in && <Alert tone="info">{t("logout.done")}</Alert>}
          <div className="flex flex-col gap-2 sm:flex-row-reverse">
            <Button type="button" busy={busy === "yes"} disabled={busy !== null} onClick={() => void decide(true)}>
              {t("logout.sign_out")}
            </Button>
            <Button type="button" variant="secondary" busy={busy === "no"} disabled={busy !== null} onClick={() => void decide(false)}>
              {t("logout.stay")}
            </Button>
          </div>
        </div>
      )}
    </AuthShell>
  );
}
