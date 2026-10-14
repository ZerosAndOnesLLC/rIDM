"use client";

import { EmptyState } from "@/components/base/empty-state";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert } from "@/components/ui";
import { Button, Card } from "@/components/console/ui";
import { needsReauth, useAccount } from "@/lib/account/session";
import { AgentLabel, DeviceIcon } from "./agent";
import { useSecurityChange } from "./security";

/** The browsers the user asked not to be asked for a second step on again. */
export function Devices() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const change = useSecurityChange();
  const devices = useQuery({
    queryKey: ["account", "devices", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/devices", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  const done = () => void qc.invalidateQueries({ queryKey: ["account", "devices", slug] });
  const revoke = useMutation({
    mutationFn: async (id: string | null) => {
      const { error } = id
        ? await client.DELETE("/t/{slug}/account/devices/{device_id}", { params: { path: { slug, device_id: id } } })
        : await client.DELETE("/t/{slug}/account/devices", { params: { path: { slug } } });
      if (error) throw error;
    },
    onSuccess: done,
    onError: (e: unknown) => {
      if (needsReauth(e)) void change.reauth();
      else setError(t("account.error_generic"));
    },
  });
  const when = (iso: string | null | undefined) => (iso ? new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(new Date(iso)) : "—");

  return (
    <Card
      title={t("account.devices_title")}
      actions={
        devices.data && devices.data.length > 0 ? (
          <Button variant="danger" onClick={() => revoke.mutate(null)} disabled={revoke.isPending}>
            {t("account.devices_revoke_all")}
          </Button>
        ) : undefined
      }
    >
      <p className="text-body text-muted">{t("account.devices_description")}</p>
      {error && <Alert tone="error">{error}</Alert>}
      {devices.isError && <Alert tone="error">{t("account.error_generic")}</Alert>}
      {devices.data && devices.data.length === 0 && <EmptyState compact title={t("account.devices_none")} />}
      {devices.data && devices.data.length > 0 && (
        <ul className="mt-3 divide-y divide-line">
          {devices.data.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
              <div className="flex min-w-0 items-center gap-3">
                <DeviceIcon ua={d.user_agent} />
                <div className="min-w-0">
                <p className="truncate text-lead font-medium text-ink">{d.name ?? <AgentLabel ua={d.user_agent} />}</p>
                <p className="text-small text-muted">
                  {t("account.device_last_used", { when: when(d.last_seen_at) })}
                  {d.ip ? ` · ${d.ip}` : ""}
                </p>
                </div>
              </div>
              <Button variant="secondary" onClick={() => revoke.mutate(d.id)} disabled={revoke.isPending}>
                {t("account.device_forget")}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
