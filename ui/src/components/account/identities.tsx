"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert } from "@/components/ui";
import { Badge, Button, Card, Modal } from "@/components/console/ui";
import { needsReauth, useAccount } from "@/lib/account/session";
import type { Schemas } from "@api/client";
import { useProblemText, useSecurityChange } from "./security";

type Linked = Schemas["LinkedIdentity"];

const LINK_ERRORS = ["denied", "upstream", "invalid_state", "email_in_use", "already_linked", "account_disabled"] as const;

/** Upstream accounts (Google, GitHub, ...) the user signs in with. */
export function Identities() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const params = useSearchParams();
  const { reauth } = useSecurityChange();
  const problemText = useProblemText();
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<Linked | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const identities = useQuery({
    queryKey: ["account", "identities", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/identities", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  const fail = (e: unknown) => {
    if (needsReauth(e)) void reauth();
    else setError(problemText(e));
  };
  const unlink = useMutation({
    mutationFn: async (idpId: string) => {
      const { error } = await client.DELETE("/t/{slug}/account/identities/{idp_id}", { params: { path: { slug, idp_id: idpId } } });
      if (error) throw error;
    },
    onSuccess: () => {
      setRemoving(null);
      void qc.invalidateQueries({ queryKey: ["account", "identities", slug] });
    },
    onError: (e: unknown) => {
      setRemoving(null);
      fail(e);
    },
  });

  const link = async (alias: string) => {
    setBusy(alias);
    setError(null);
    try {
      const { data, error } = await client.POST("/t/{slug}/account/identities/link", {
        params: { path: { slug } },
        body: { alias, return_to: `${window.location.pathname}` },
      });
      if (error) throw error;
      // The provider brings the browser back here with `?linked=1` or `?link_error=`.
      window.location.assign(data.url);
    } catch (e) {
      fail(e);
      setBusy(null);
    }
  };

  const when = (iso: string | null | undefined) => (iso ? new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(new Date(iso)) : null);
  const linkError = params.get("link_error");
  const linked = params.get("linked") === "1";
  const d = identities.data;
  if (d && d.linked.length === 0 && d.available.length === 0 && !linkError) return null;

  return (
    <>
      <Card title={t("account.identities_title")}>
        <p className="text-[0.875rem] text-muted">{t("account.identities_description")}</p>
        {linked && (
          <div className="mt-3">
            <Alert tone="ok">{t("account.identities_linked")}</Alert>
          </div>
        )}
        {linkError && (
          <div className="mt-3">
            <Alert tone="error">{t(LINK_ERRORS.includes(linkError as (typeof LINK_ERRORS)[number]) ? `login.broker.${linkError}` : "account.error_generic")}</Alert>
          </div>
        )}
        {error && (
          <div className="mt-3">
            <Alert tone="error">{error}</Alert>
          </div>
        )}
        {identities.isError && <Alert tone="error">{t("account.error_generic")}</Alert>}
        {d && d.linked.length > 0 && (
          <ul aria-label={t("account.identities_title")} className="mt-3 divide-y divide-line">
            {d.linked.map((i) => (
              <li key={i.idp_id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2 text-[0.9375rem] font-medium text-ink">
                    <span>{i.display_name}</span>
                    {(i.external_email ?? i.external_username) && <Badge>{i.external_email ?? i.external_username}</Badge>}
                  </p>
                  <p className="text-[0.8125rem] text-muted">
                    {t("account.identity_linked_at", { when: when(i.linked_at) ?? "" })}
                    {i.last_login_at ? ` · ${t("account.identity_last_used", { when: when(i.last_login_at) ?? "" })}` : ""}
                  </p>
                </div>
                <Button variant="secondary" onClick={() => setRemoving(i)}>
                  {t("account.identity_unlink")}
                </Button>
              </li>
            ))}
          </ul>
        )}
        {d && d.available.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {d.available.map((p) => (
              <Button key={p.alias} variant={d.linked.length === 0 ? "primary" : "secondary"} disabled={busy !== null} onClick={() => void link(p.alias)}>
                {t("account.identity_link", { name: p.display_name })}
              </Button>
            ))}
          </div>
        )}
      </Card>
      <Modal open={removing !== null} onOpenChange={(o) => !o && setRemoving(null)} title={t("account.identity_unlink_title", { name: removing?.display_name ?? "" })}>
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <p className="text-[0.9375rem] text-ink">{t("account.identity_unlink_hint")}</p>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setRemoving(null)}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" onClick={() => removing && unlink.mutate(removing.idp_id)} disabled={unlink.isPending}>
              {t("account.identity_unlink")}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
