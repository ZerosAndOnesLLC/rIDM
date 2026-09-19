"use client";

import { useQuery } from "@tanstack/react-query";
import { useI18n } from "@/i18n/provider";
import { Alert } from "@/components/ui";
import { Badge, Card } from "@/components/console/ui";
import { useAccount } from "@/lib/account/session";
import { useProblemText } from "./security";

/** The organizations the user belongs to. Read-only: membership is granted. */
export function Organizations() {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const problemText = useProblemText();
  const orgs = useQuery({
    queryKey: ["account", "organizations", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/organizations", {
        params: { path: { slug } },
      });
      if (error) throw error;
      return data;
    },
  });
  if (orgs.isError) return <Alert tone="error">{problemText(orgs.error)}</Alert>;
  return (
    <Card title={t("account.orgs")}>
      <p className="text-[0.875rem] text-muted">{t("account.orgs_description")}</p>
      {orgs.data && orgs.data.length === 0 ? (
        <p className="mt-3 text-[0.875rem] text-muted">{t("account.orgs_none")}</p>
      ) : (
        <ul className="mt-3 divide-y divide-line">
          {(orgs.data ?? []).map((o) => (
            <li key={o.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
              <span className="flex flex-col">
                <span className="text-ink">
                  {o.display_name} {o.primary && <Badge>{t("account.orgs_primary")}</Badge>}
                </span>
                <span className="text-[0.8125rem] text-muted">{o.slug}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
