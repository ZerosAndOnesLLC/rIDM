"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";
import { NumberInput, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import type { ScimToken } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";
import { CopyButton, RevealModal, type Revealed } from "../clients/reveal";

/** SCIM 2.0 provisioning: the tenant's endpoint and the bearer tokens a provisioning system uses against it. */
export function ProvisioningPage({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const editable = can("ridm:scim:write");
  const tokens = useQuery({
    queryKey: ["scim-tokens", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/scim/tokens", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [name, setName] = useState("");
  const [days, setDays] = useState<number | null>(365);
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["scim-tokens", tenant] });
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/scim/tokens", { params: { path: { slug: tenant } }, body: { name: name.trim(), expires_in_days: days } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (t) => {
      setName("");
      invalidate();
      setRevealed({ title: `${t.name} created`, description: "Configure the provisioning system with this bearer token; it is shown only now.", values: [{ label: "Provisioning token", value: t.token }] });
    },
  });
  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/scim/tokens/{token}", { params: { path: { slug: tenant, token: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: invalidate,
  });
  const state = (t: ScimToken): { label: string; tone: "neutral" | "danger" | "ok" } => {
    if (t.revoked_at) return { label: "revoked", tone: "neutral" };
    if (t.expires_at && new Date(t.expires_at) < new Date()) return { label: "expired", tone: "danger" };
    return { label: "active", tone: "ok" };
  };
  return (
    <>
      <PageHeader title="Provisioning" sub="SCIM 2.0: let an identity system such as Entra ID, Okta or OneLogin create, update, deactivate and group users here. Point it at the endpoint below with a provisioning token as its bearer credential." />
      <RevealModal revealed={revealed} onClose={() => setRevealed(null)} />
      <ErrorLine error={create.error ?? revoke.error} />
      {tokens.isPending ? (
        <Spinner label="Loading…" />
      ) : tokens.isError ? (
        <ErrorLine error={tokens.error} />
      ) : (
        <div className="flex flex-col gap-6">
          <Card title="Endpoint">
            <div className="flex flex-wrap items-center gap-2 text-[0.875rem]">
              <code className="rounded-[var(--radius)] bg-ground px-2 py-1 font-mono text-[0.8125rem] text-ink" aria-label="SCIM base URL">
                {tokens.data.base_url}
              </code>
              <CopyButton value={tokens.data.base_url} label="Copy the SCIM base URL" />
            </div>
            <p className="mt-2 text-[0.8125rem] text-muted">
              Users map onto userName, externalId, emails, phoneNumbers, active and locale; givenName, familyName and displayName are stored when the profile schema declares given_name, family_name and display_name. Groups map onto displayName, externalId and members.
            </p>
          </Card>
          {editable && (
            <Card title="New token">
              <form
                className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_10rem_auto] sm:items-end"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (name.trim()) create.mutate();
                }}
              >
                <label className="flex flex-col gap-1 text-[0.8125rem] text-muted">
                  Name
                  <TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="Entra ID" required />
                </label>
                <label className="flex flex-col gap-1 text-[0.8125rem] text-muted">
                  Expires in
                  <NumberInput id="scim-token-days" value={days} min={1} max={3650} nullable onValue={setDays} unit="days" />
                </label>
                <Button type="submit" disabled={create.isPending || !name.trim()}>
                  <Plus className="size-4" aria-hidden /> Create token
                </Button>
              </form>
            </Card>
          )}
          <Card title="Tokens">
            {tokens.data.tokens.length === 0 ? (
              <p className="text-[0.875rem] text-muted">No provisioning tokens yet.</p>
            ) : (
              <ul className="divide-y divide-line">
                {tokens.data.tokens.map((t) => {
                  const s = state(t);
                  return (
                    <li key={t.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-[0.875rem]">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-ink">{t.name}</span>
                        <Badge tone={s.tone}>{s.label}</Badge>
                        <span className="text-[0.8125rem] text-muted">
                          created {formatDate("en", t.created_at)}
                          {t.expires_at ? ` · expires ${formatDate("en", t.expires_at)}` : " · no expiry"}
                          {t.last_used_at ? ` · last used ${formatDate("en", t.last_used_at)}` : " · never used"}
                        </span>
                      </div>
                      {editable && !t.revoked_at && (
                        <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate(t.id)}>
                          Revoke
                        </Button>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
