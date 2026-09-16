"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Button } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useConsole } from "@/lib/console/session";

/** The upstream identities linked to a user, with unlinking. */
export function LinkedIdentities({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["user", tenant, id, "identities"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/users/{user}/identities", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const unlink = useMutation({
    mutationFn: async (idpId: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/users/{user}/identities/{idp_id}", { params: { path: { slug: tenant, user: id, idp_id: idpId } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["user", tenant, id, "identities"] }),
  });
  return (
    <div className="mt-4 border-t border-line pt-3">
      <h3 className="text-[0.875rem] font-semibold text-ink">Linked identities</h3>
      {list.isPending ? (
        <Spinner label="Loading…" />
      ) : list.isError ? (
        <p role="alert" className="mt-1 text-[0.875rem] text-danger">
          {list.error.message}
        </p>
      ) : list.data.length === 0 ? (
        <p className="mt-1 text-[0.8125rem] text-muted">No upstream identity is linked.</p>
      ) : (
        <ul aria-label="Linked identities" className="mt-1 divide-y divide-line">
          {list.data.map((i) => (
            <li key={i.idp_id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-[0.875rem]">
              <span className="flex min-w-0 flex-col">
                <span className="flex flex-wrap items-center gap-2 text-ink">
                  <span className="font-medium">{i.display_name}</span>
                  <Badge>{i.alias}</Badge>
                  {(i.external_email ?? i.external_username) && <span className="text-muted">{i.external_email ?? i.external_username}</span>}
                </span>
                <span className="text-[0.8125rem] text-muted">
                  Subject {i.external_subject} · linked {formatDate("en", i.linked_at)}
                  {i.last_login_at ? ` · last sign-in ${formatDate("en", i.last_login_at)}` : ""}
                </span>
              </span>
              {editable && (
                <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={unlink.isPending} onClick={() => unlink.mutate(i.idp_id)}>
                  Unlink
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {unlink.isError && (
        <p role="alert" className="mt-2 text-[0.875rem] text-danger">
          {unlink.error.message}
        </p>
      )}
    </div>
  );
}
