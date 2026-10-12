"use client";

import { fmtDateTime } from "@/lib/console/format";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Mail } from "lucide-react";
import { useState, type FormEvent } from "react";
import { DataTable, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { Field, NumberInput, TextInput } from "@/components/console/form";
import { Badge, Button, Modal } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";
import { roleName } from "@/lib/console/users";
import { CheckList } from "../clients/pickers";

export function useRolesAndGroups(tenant: string) {
  const { client } = useConsole();
  const roles = useQuery({
    queryKey: ["roles", tenant],
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/roles", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const groups = useQuery({
    queryKey: ["groups", tenant],
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/groups", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  return { roles, groups };
}

/** Invite by email, optionally straight into roles and groups. */
export function InviteUser({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const { roles, groups } = useRolesAndGroups(tenant);
  const [email, setEmail] = useState("");
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [days, setDays] = useState<number | null>(7);
  const [sent, setSent] = useState<string | null>(null);
  const invite = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/invitations", {
        params: { path: { slug: tenant } },
        body: { email: email.trim(), roles: roleIds, groups: groupIds, expires_days: days, org_id: null },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (inv) => {
      void qc.invalidateQueries({ queryKey: ["invitations", tenant] });
      setSent(inv.email);
      setEmail("");
      setRoleIds([]);
      setGroupIds([]);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;
    setSent(null);
    invite.mutate();
  };
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Invite someone" description="They receive an email with a link to set up their account.">
      <form onSubmit={submit} className="flex flex-col gap-4 overflow-y-auto px-5 pb-5 pt-3" noValidate>
        {sent && (
          <p role="status" className="rounded-[var(--radius)] bg-ok-soft px-3.5 py-2.5 text-body text-ok">
            Invitation sent to {sent}.
          </p>
        )}
        <Field label="Email">{(id) => <TextInput id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required />}</Field>
        <Field label="Expires after">{(id) => <NumberInput id={id} value={days} min={1} max={365} nullable onValue={setDays} unit="days" />}</Field>
        <CheckList legend="Roles" options={(roles.data ?? []).map((r) => ({ value: r.id, label: roleName(r), hint: r.description ?? undefined }))} value={roleIds} onChange={setRoleIds} />
        <CheckList legend="Groups" options={(groups.data ?? []).map((g) => ({ value: g.id, label: g.name }))} value={groupIds} onChange={setGroupIds} />
        {invite.isError && (
          <p role="alert" className="text-body text-danger">
            {invite.error.message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Done</Button>
          <Button type="submit" variant="primary" disabled={invite.isPending}>
            {invite.isPending ? "Sending…" : "Send invitation"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

/** Open invitations with resend and revoke. */
export function InvitationsList({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["invitations", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/invitations", { params: { path: { slug: tenant }, query: { open_only: true, limit: 100 } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data.items;
    },
  });
  const resend = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.POST("/admin/tenants/{slug}/invitations/{invitation}/resend", { params: { path: { slug: tenant, invitation: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["invitations", tenant] }),
  });
  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/invitations/{invitation}", { params: { path: { slug: tenant, invitation: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["invitations", tenant] }),
  });
  if (list.isError)
    return (
      <p role="alert" className="text-lead text-danger">
        {list.error.message}
      </p>
    );
  const writer = can("ridm:invitations:write");
  const err = resend.error ?? revoke.error;
  type Row = NonNullable<typeof list.data>[number];
  const columns: Column<Row>[] = [
    { key: "email", header: "Email", width: "minmax(12rem, 2fr)", cell: (i) => <span className="truncate font-medium text-ink">{i.email}</span> },
    { key: "sent", header: "Sent", width: "minmax(8rem, 1fr)", cell: (i) => <span className="text-muted">{fmtDateTime(i.created_at)}</span> },
    { key: "expires", header: "Expires", width: "minmax(8rem, 1fr)", cell: (i) => (new Date(i.expires_at) < new Date() ? <Badge tone="danger">Expired</Badge> : <span className="text-muted">{fmtDateTime(i.expires_at)}</span>) },
    {
      key: "grants",
      header: "Roles / groups",
      width: "7rem",
      cell: (i) => (
        <span className="text-muted">
          {i.roles.length} / {i.groups.length}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      hideHeader: true,
      width: "10rem",
      align: "end",
      cell: (i) =>
        writer ? (
          <span className="inline-flex gap-1.5">
            <Button className="min-h-7 px-2.5 text-caption" disabled={resend.isPending} onClick={() => resend.mutate(i.id)}>
              Resend
            </Button>
            <Button variant="danger" className="min-h-7 px-2.5 text-caption" disabled={revoke.isPending} onClick={() => revoke.mutate(i.id)}>
              Revoke
            </Button>
          </span>
        ) : null,
    },
  ];
  return (
    <>
      {err && (
        <p role="alert" className="mb-3 text-body text-danger">
          {err.message}
        </p>
      )}
      <DataTable
        label="Invitations"
        columns={columns}
        rows={list.data ?? []}
        rowKey={(i) => i.id}
        loading={list.isPending}
        minWidth="44rem"
        empty={<EmptyState icon={Mail} title="No open invitations" description="Invitations that were accepted, revoked or expired are not listed." />}
      />
    </>
  );
}
