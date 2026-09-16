"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert } from "@/components/ui";
import { Badge, Button, Card, Modal } from "@/components/console/ui";
import { useAccount } from "@/lib/account/session";
import { useProblemText } from "./security";
import type { Schemas } from "@api/client";

type App = Schemas["ConsentedApp"];

/** The applications the user granted access to, and taking that access back. */
export function Apps() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const problemText = useProblemText();
  const [removing, setRemoving] = useState<App | null>(null);
  const [error, setError] = useState<string | null>(null);
  const apps = useQuery({
    queryKey: ["account", "apps", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/apps", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/t/{slug}/account/apps/{client_id}", { params: { path: { slug, client_id: id } } });
      if (error) throw error;
    },
    onSuccess: () => {
      setRemoving(null);
      void qc.invalidateQueries({ queryKey: ["account", "apps", slug] });
    },
    onError: (e: unknown) => {
      setRemoving(null);
      setError(problemText(e));
    },
  });
  const when = (iso: string) => new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(new Date(iso));

  return (
    <>
      <Card title={t("account.apps_title")}>
        <p className="text-[0.875rem] text-muted">{t("account.apps_description")}</p>
        {error && (
          <div className="mt-3">
            <Alert tone="error">{error}</Alert>
          </div>
        )}
        {apps.isError && <Alert tone="error">{t("account.error_generic")}</Alert>}
        {apps.data && apps.data.length === 0 && <p className="mt-3 text-[0.875rem] text-ink">{t("account.apps_none")}</p>}
        {apps.data && apps.data.length > 0 && (
          <ul aria-label={t("account.apps_title")} className="mt-3 divide-y divide-line">
            {apps.data.map((a) => (
              <li key={a.client_id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="flex min-w-0 items-center gap-3">
                  {a.logo_uri ? (
                    // eslint-disable-next-line @next/next/no-img-element -- a third party's logo at its own URL
                    <img src={a.logo_uri} alt="" className="size-9 shrink-0 rounded-md border border-line object-cover" />
                  ) : (
                    <span aria-hidden className="flex size-9 shrink-0 items-center justify-center rounded-md bg-ground text-[0.9375rem] font-semibold text-muted">
                      {a.name.slice(0, 1).toUpperCase()}
                    </span>
                  )}
                  <div className="min-w-0">
                    <p className="truncate text-[0.9375rem] font-medium text-ink">{a.name}</p>
                    <p className="flex flex-wrap items-center gap-1.5 text-[0.8125rem] text-muted">
                      <span>{t("account.app_granted", { when: when(a.granted_at) })}</span>
                      {a.scopes.map((s) => (
                        <Badge key={s}>{s}</Badge>
                      ))}
                    </p>
                    {(a.policy_uri || a.tos_uri) && (
                      <p className="mt-0.5 flex gap-3 text-[0.8125rem]">
                        {a.policy_uri && (
                          <a href={a.policy_uri} target="_blank" rel="noreferrer" className="text-link hover:underline underline-offset-4">
                            {t("account.app_privacy")}
                          </a>
                        )}
                        {a.tos_uri && (
                          <a href={a.tos_uri} target="_blank" rel="noreferrer" className="text-link hover:underline underline-offset-4">
                            {t("account.app_terms")}
                          </a>
                        )}
                      </p>
                    )}
                  </div>
                </div>
                <Button variant="secondary" onClick={() => setRemoving(a)}>
                  {t("account.app_remove")}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Modal open={removing !== null} onOpenChange={(o) => !o && setRemoving(null)} title={t("account.app_remove_title", { name: removing?.name ?? "" })}>
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <p className="text-[0.9375rem] text-ink">{t("account.app_remove_hint")}</p>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setRemoving(null)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" onClick={() => removing && revoke.mutate(removing.client_id)} disabled={revoke.isPending}>
              {t("account.app_remove")}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
