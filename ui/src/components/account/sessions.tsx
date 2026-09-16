"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert } from "@/components/ui";
import { Badge, Button, Card } from "@/components/console/ui";
import { needsReauth, useAccount } from "@/lib/account/session";
import { useProblemText, useSecurityChange } from "./security";

/** Where the user is signed in, and the means to end it. */
export function Sessions() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const { reauth } = useSecurityChange();
  const problemText = useProblemText();
  const sessions = useQuery({
    queryKey: ["account", "sessions", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/sessions", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  const done = () => void qc.invalidateQueries({ queryKey: ["account", "sessions", slug] });
  const end = useMutation({
    mutationFn: async (id: string | null) => {
      const { error } = id
        ? await client.DELETE("/t/{slug}/account/sessions/{session_id}", { params: { path: { slug, session_id: id } } })
        : await client.DELETE("/t/{slug}/account/sessions", { params: { path: { slug }, query: { keep_current: true } } });
      if (error) throw error;
    },
    onSuccess: done,
    onError: (e: unknown) => {
      if (needsReauth(e)) void reauth();
      else setError(problemText(e));
    },
  });
  const when = (iso: string) => new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(new Date(iso));
  const list = sessions.data ?? [];
  const others = list.filter((s) => !s.current).length;

  return (
    <Card
      title={t("account.sessions_title")}
      actions={
        others > 0 ? (
          <Button variant="danger" onClick={() => end.mutate(null)} disabled={end.isPending}>
            {t("account.sessions_end_others")}
          </Button>
        ) : undefined
      }
    >
      <p className="text-[0.875rem] text-muted">{t("account.sessions_description")}</p>
      {error && (
        <div className="mt-3">
          <Alert tone="error">{error}</Alert>
        </div>
      )}
      {sessions.isError && <Alert tone="error">{t("account.error_generic")}</Alert>}
      {list.length > 0 && (
        <ul aria-label={t("account.sessions_title")} className="mt-3 divide-y divide-line">
          {list.map((s) => (
            <li key={s.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-[0.9375rem] font-medium text-ink">
                  <span className="truncate">{s.user_agent ?? t("account.device_unnamed")}</span>
                  {s.current && <Badge tone="accent">{t("account.session_current")}</Badge>}
                </p>
                <p className="text-[0.8125rem] text-muted">
                  {t("account.session_signed_in", { when: when(s.auth_time) })}
                  {s.ip ? ` · ${s.ip}` : ""}
                  {` · ${t("account.session_last_seen", { when: when(s.last_seen_at) })}`}
                </p>
              </div>
              {!s.current && (
                <Button variant="secondary" onClick={() => end.mutate(s.id)} disabled={end.isPending}>
                  {t("account.session_end")}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
