"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Network, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { BulkBar, bulkButtonClass } from "@/components/base/bulk-bar";
import { ConfirmDialog } from "@/components/base/confirm-dialog";
import { DataTable, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { useToast } from "@/components/base/toast";
import { bulkToast, runBulk } from "@/lib/console/bulk";
import { SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, IconButton, PageHeader } from "@/components/console/ui";
import { useClientNames } from "@/lib/console/hooks";
import type { IpRule } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

/** Allow and deny rules per CIDR, tenant-wide or per client (enforced from Phase 9.2). */
export function IpRulesPage({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const { toast } = useToast();
  const editable = can("ridm:tenants:write");
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [confirm, setConfirm] = useState<{ ids: string[]; label: string } | null>(null);
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
  const names = clients.data ?? {};
  const removeAll = async (ids: string[]) => {
    const result = await runBulk(ids, async (id) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/ip-rules/{rule}", { params: { path: { slug: tenant, rule: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    });
    toast(bulkToast(result, "deleted", ["rule", "rules"]));
    setSelected(new Set());
    invalidate();
  };

  const columns: Column<IpRule>[] = [
    { key: "cidr", header: "Network", width: "minmax(9rem, 1fr)", cell: (r) => <span className="font-mono text-small text-ink">{r.cidr}</span> },
    {
      key: "action",
      header: "Action",
      width: "7.5rem",
      cell: (r) =>
        editable ? (
          <SelectInput aria-label={`Action for ${r.cidr}`} value={r.action} onChange={(e) => patch.mutate({ id: r.id, body: { action: e.target.value as "allow" | "deny" } })} className="min-h-8 max-w-[7rem] text-small">
            <option value="deny">Deny</option>
            <option value="allow">Allow</option>
          </SelectInput>
        ) : (
          <Badge tone={r.action === "allow" ? "ok" : "danger"}>{r.action}</Badge>
        ),
    },
    { key: "scope", header: "Applies to", width: "minmax(8rem, 1fr)", cell: (r) => <span className="truncate text-muted">{r.client_id ? (names[r.client_id] ?? "one client") : "Whole tenant"}</span> },
    {
      key: "description",
      header: "Description",
      width: "minmax(10rem, 2fr)",
      cell: (r) => (editable ? <DescriptionInput r={r} onPatch={(d) => patch.mutate({ id: r.id, body: { description: d } })} /> : <span className="truncate text-muted">{r.description ?? "—"}</span>),
    },
    {
      key: "actions",
      header: "Actions",
      hideHeader: true,
      width: "2.5rem",
      align: "end",
      cell: (r) =>
        editable ? (
          <IconButton label={`Delete rule ${r.cidr}`} onClick={() => setConfirm({ ids: [r.id], label: `the rule for ${r.cidr}` })} className="text-danger hover:bg-danger-soft">
            <Trash2 className="size-4" aria-hidden />
          </IconButton>
        ) : null,
    },
  ];

  return (
    <>
      <PageHeader title="IP rules" sub="Allow and deny networks for the whole tenant or one client, enforced on sign-in, authorization and token requests. The most specific matching network decides; once a scope has an allow rule, every other address is refused." />
      <ErrorLine error={add.error ?? patch.error} />
      {rules.isError ? (
        <ErrorLine error={rules.error} />
      ) : (
        <DataTable
          label="IP rules"
          columns={columns}
          rows={rules.data ?? []}
          rowKey={(r) => r.id}
          loading={rules.isPending}
          selection={editable ? { selected, onChange: setSelected, name: (r) => r.cidr } : undefined}
          empty={<EmptyState icon={Network} title="No rules yet" description={editable ? "Every address is allowed until a rule says otherwise. Add the first one below." : "Every address is allowed until a rule says otherwise."} />}
        />
      )}
      {editable && !rules.isPending && (
        <form
          className="mt-3 flex flex-wrap items-center gap-2 rounded-[var(--radius)] border border-line bg-paper p-3"
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
      <BulkBar count={selected.size} label="Selected rules" onClear={() => setSelected(new Set())}>
        <button type="button" className={bulkButtonClass(true)} onClick={() => setConfirm({ ids: [...selected], label: `${selected.size} ${selected.size === 1 ? "rule" : "rules"}` })}>
          Delete
        </button>
      </BulkBar>
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Delete ${confirm?.label ?? ""}?`}
        description="Addresses the rule covered are judged by the remaining rules from now on."
        confirmLabel="Delete"
        onConfirm={() => removeAll(confirm?.ids ?? [])}
      />
    </>
  );
}

/** The rule's description, saved when the field is left. */
function DescriptionInput({ r, onPatch }: { r: IpRule; onPatch: (d: string | null) => void }) {
  const [description, setDescription] = useState(r.description ?? "");
  return (
    <TextInput
      aria-label={`Description for ${r.cidr}`}
      value={description}
      onChange={(e) => setDescription(e.target.value)}
      onBlur={() => (description || null) !== (r.description ?? null) && onPatch(description || null)}
      className="min-h-8 text-small"
    />
  );
}
