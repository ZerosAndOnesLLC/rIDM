"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert } from "@/components/ui";
import { Badge, Button, Card } from "@/components/console/ui";
import { useAccount } from "@/lib/account/session";
import { useProblemText } from "./security";
import type { Schemas } from "@api/client";

type Request = Schemas["PendingRequest"];

/** Sign-in requests applications sent over the back channel (CIBA), each waiting on a yes or no. */
export function Approvals() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const problemText = useProblemText();
  const focus = useSearchParams().get("request");
  const [error, setError] = useState<string | null>(null);
  const [answered, setAnswered] = useState<{ name: string; approved: boolean } | null>(null);
  const requests = useQuery({
    queryKey: ["account", "approvals", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/backchannel-requests", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
    // A new request should show up while the page is open (a sign-in on
    // another device is waiting on it); a hidden tab does not poll.
    refetchInterval: 10_000,
  });
  const answer = useMutation({
    mutationFn: async ({ r, approve }: { r: Request; approve: boolean }) => {
      const path = approve ? "/t/{slug}/account/backchannel-requests/{id}/approve" : "/t/{slug}/account/backchannel-requests/{id}/deny";
      const { error } = await client.POST(path, { params: { path: { slug, id: r.id } } });
      if (error) throw error;
    },
    onSuccess: (_, { r, approve }) => {
      setError(null);
      setAnswered({ name: r.client_name, approved: approve });
      void qc.invalidateQueries({ queryKey: ["account", "approvals", slug] });
      void qc.invalidateQueries({ queryKey: ["account", "apps", slug] });
    },
    onError: (e: unknown) => {
      setError(problemText(e));
      void qc.invalidateQueries({ queryKey: ["account", "approvals", slug] });
    },
  });
  const time = (iso: string) => new Intl.DateTimeFormat(locale, { timeStyle: "short" }).format(new Date(iso));
  const list = requests.data ?? [];
  const ordered = focus ? [...list.filter((r) => r.id === focus), ...list.filter((r) => r.id !== focus)] : list;

  return (
    <Card title={t("account.approvals_title")}>
      <p className="text-[0.875rem] text-muted">{t("account.approvals_description")}</p>
      {answered && (
        <div className="mt-3">
          <Alert tone={answered.approved ? "ok" : "info"}>
            {t(answered.approved ? "account.approval_approved" : "account.approval_denied", { name: answered.name })}
          </Alert>
        </div>
      )}
      {error && (
        <div className="mt-3">
          <Alert tone="error">{error}</Alert>
        </div>
      )}
      {requests.isError && <Alert tone="error">{t("account.error_generic")}</Alert>}
      {requests.data && list.length === 0 && <p className="mt-3 text-[0.875rem] text-ink">{t("account.approvals_none")}</p>}
      {list.length > 0 && (
        <ul aria-label={t("account.approvals_title")} className="mt-3 divide-y divide-line">
          {ordered.map((r) => (
            <li key={r.id} className={`flex flex-col gap-3 py-4 ${r.id === focus ? "rounded-md bg-ground px-3" : ""}`}>
              <div className="flex min-w-0 items-center gap-3">
                {r.logo_uri ? (
                  // eslint-disable-next-line @next/next/no-img-element -- a third party's logo at its own URL
                  <img src={r.logo_uri} alt="" className="size-9 shrink-0 rounded-md border border-line object-cover" />
                ) : (
                  <span aria-hidden className="flex size-9 shrink-0 items-center justify-center rounded-md bg-paper text-[0.9375rem] font-semibold text-muted">
                    {r.client_name.slice(0, 1).toUpperCase()}
                  </span>
                )}
                <div className="min-w-0">
                  <p className="truncate text-[0.9375rem] font-medium text-ink">{t("account.approval_asks", { name: r.client_name })}</p>
                  <p className="text-[0.8125rem] text-muted">{t("account.approval_times", { asked: time(r.created_at), expires: time(r.expires_at) })}</p>
                </div>
              </div>
              {r.binding_message && (
                <div className="rounded-md border border-line bg-paper px-3 py-2">
                  <p className="text-[0.8125rem] text-muted">{t("account.approval_binding")}</p>
                  <p className="font-mono text-[1.125rem] font-semibold tracking-wide text-ink">{r.binding_message}</p>
                </div>
              )}
              <p className="flex flex-wrap items-center gap-1.5 text-[0.8125rem] text-muted">
                <span>{t("account.approval_scopes")}</span>
                {r.scopes.map((s) => (
                  <Badge key={s}>{s}</Badge>
                ))}
              </p>
              <p className="text-[0.8125rem] text-muted">{t("account.approval_hint")}</p>
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => answer.mutate({ r, approve: true })} disabled={answer.isPending}>
                  {t("account.approval_approve")}
                </Button>
                <Button variant="secondary" onClick={() => answer.mutate({ r, approve: false })} disabled={answer.isPending}>
                  {t("account.approval_deny")}
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
