"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, IconButton, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useClientNames } from "@/lib/console/hooks";
import type { IpRule } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

/** Allow and deny rules per CIDR, tenant-wide or per client (enforced from Phase 9.2). */
export function IpRulesPage({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const editable = can("ridm:tenants:write");
  const rules = useQuery({
    queryKey: ["ip-rules", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/ip-rules", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const clients = useClientNames(tenant);

  const [cidr, setCidr] = useState("");
  const [action, setAction] = useState<"allow" | "deny">("deny");
  const [clientId, setClientId] = useState("");
  const [description, setDescription] = useState("");
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["ip-rules", tenant] });
  const add = useMutation({
    mutationFn: async () => {
      const { error } = await client.POST("/admin/tenants/{slug}/ip-rules", { params: { path: { slug: tenant } }, body: { cidr: cidr.trim(), action, client_id: clientId || null, description: description.trim() || null } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setCidr("");
      setDescription("");
      invalidate();
    },
  });
  const patch = useMutation({
    mutationFn: async ({ id, body }: { id: string; body: { action?: "allow" | "deny"; description?: string | null; cidr?: string } }) => {
      const { error } = await client.PATCH("/admin/tenants/{slug}/ip-rules/{rule}", { params: { path: { slug: tenant, rule: id } }, body: body as never });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/ip-rules/{rule}", { params: { path: { slug: tenant, rule: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: invalidate,
  });
  const names = clients.data ?? {};
  return (
    <>
      <PageHeader title="IP rules" sub="Allow and deny networks for the whole tenant or one client, enforced on sign-in, authorization and token requests. The most specific matching network decides; once a scope has an allow rule, every other address is refused." />
      <ErrorLine error={add.error ?? patch.error ?? remove.error} />
      {rules.isPending ? (
        <Spinner label="Loading…" />
      ) : rules.isError ? (
        <ErrorLine error={rules.error} />
      ) : (
        <div className="overflow-x-auto rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
          <table className="w-full text-[0.875rem]">
            <thead className="text-[0.75rem] uppercase tracking-wide text-muted">
              <tr className="border-b border-line">
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Network</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Action</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Applies to</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Description</th>
                <th scope="col" className="px-4 py-2.5 text-end font-medium"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {rules.data.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted">No rules yet.</td>
                </tr>
              )}
              {rules.data.map((r) => (
                <RuleRow key={r.id} r={r} clientName={r.client_id ? (names[r.client_id] ?? "one client") : "Whole tenant"} editable={editable} onPatch={(body) => patch.mutate({ id: r.id, body })} onRemove={() => remove.mutate(r.id)} />
              ))}
            </tbody>
          </table>
          {editable && (
            <form
              className="flex flex-wrap items-center gap-2 border-t border-line p-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (cidr.trim()) add.mutate();
              }}
            >
              <TextInput aria-label="Network (CIDR)" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="203.0.113.0/24" spellCheck={false} className="max-w-[14rem]" />
              <SelectInput aria-label="Action" value={action} onChange={(e) => setAction(e.target.value as "allow" | "deny")} className="max-w-[8rem]">
                <option value="deny">Deny</option>
                <option value="allow">Allow</option>
              </SelectInput>
              <SelectInput aria-label="Applies to" value={clientId} onChange={(e) => setClientId(e.target.value)} className="max-w-[14rem]">
                <option value="">Whole tenant</option>
                {Object.entries(names)
                  .sort((a, b) => a[1].localeCompare(b[1]))
                  .map(([id, n]) => (
                    <option key={id} value={id}>
                      {n}
                    </option>
                  ))}
              </SelectInput>
              <TextInput aria-label="Description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Office network" className="min-w-[10rem] flex-1" />
              <Button type="submit" variant="primary" disabled={!cidr.trim() || add.isPending}>
                <Plus className="size-4" aria-hidden />
                Add rule
              </Button>
            </form>
          )}
        </div>
      )}
    </>
  );
}

function RuleRow({ r, clientName, editable, onPatch, onRemove }: { r: IpRule; clientName: string; editable: boolean; onPatch: (b: { action?: "allow" | "deny"; description?: string | null }) => void; onRemove: () => void }) {
  const [description, setDescription] = useState(r.description ?? "");
  return (
    <tr className="border-b border-line last:border-b-0">
      <td className="px-4 py-2 font-mono text-[0.8125rem] text-ink">{r.cidr}</td>
      <td className="px-4 py-2">
        {editable ? (
          <SelectInput aria-label={`Action for ${r.cidr}`} value={r.action} onChange={(e) => onPatch({ action: e.target.value as "allow" | "deny" })} className="max-w-[7rem]">
            <option value="deny">Deny</option>
            <option value="allow">Allow</option>
          </SelectInput>
        ) : (
          <Badge tone={r.action === "allow" ? "ok" : "danger"}>{r.action}</Badge>
        )}
      </td>
      <td className="px-4 py-2 text-muted">{clientName}</td>
      <td className="px-4 py-2">
        {editable ? (
          <TextInput aria-label={`Description for ${r.cidr}`} value={description} onChange={(e) => setDescription(e.target.value)} onBlur={() => (description || null) !== (r.description ?? null) && onPatch({ description: description || null })} />
        ) : (
          <span className="text-muted">{r.description ?? "—"}</span>
        )}
      </td>
      <td className="px-4 py-2 text-end">
        {editable && (
          <IconButton label={`Delete rule ${r.cidr}`} onClick={onRemove} className="text-danger hover:bg-danger-soft">
            <Trash2 className="size-4" aria-hidden />
          </IconButton>
        )}
      </td>
    </tr>
  );
}
