"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Button } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useConsole } from "@/lib/console/session";

/** A user's personal access tokens (metadata only), with revocation. */
export function PersonalTokens({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["user", tenant, id, "pats"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/users/{user}/pats", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const revoke = useMutation({
    mutationFn: async (tokenId: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/users/{user}/pats/{token_id}", { params: { path: { slug: tenant, user: id, token_id: tokenId } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["user", tenant, id, "pats"] }),
  });
  const live = (list.data ?? []).filter((k) => !k.revoked_at);
  return (
    <div className="mt-4 border-t border-line pt-3">
      <h3 className="text-[0.875rem] font-semibold text-ink">Personal access tokens</h3>
      {list.isPending ? (
        <Spinner label="Loading…" />
      ) : list.isError ? (
        <p role="alert" className="mt-1 text-[0.875rem] text-danger">
          {list.error.message}
        </p>
      ) : live.length === 0 ? (
        <p className="mt-1 text-[0.8125rem] text-muted">No live personal access tokens.</p>
      ) : (
        <ul aria-label="Personal access tokens" className="mt-1 divide-y divide-line">
          {live.map((k) => (
            <li key={k.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-[0.875rem]">
              <span className="flex min-w-0 flex-col">
                <span className="flex flex-wrap items-center gap-2 text-ink">
                  <span className="font-medium">{k.name}</span>
                  {k.scopes.map((s) => (
                    <Badge key={s}>{s}</Badge>
                  ))}
                </span>
                <span className="text-[0.8125rem] text-muted">
                  Created {formatDate("en", k.created_at)}
                  {k.expires_at ? ` · expires ${formatDate("en", k.expires_at)}` : " · never expires"}
                  {k.last_used_at ? ` · last used ${formatDate("en", k.last_used_at)}` : " · never used"}
                </span>
              </span>
              {editable && (
                <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate(k.id)}>
                  Revoke
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {revoke.isError && (
        <p role="alert" className="mt-2 text-[0.875rem] text-danger">
          {revoke.error.message}
        </p>
      )}
    </div>
  );
}
