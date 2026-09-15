"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Field, NumberInput, TextInput } from "@/components/console/form";
import { Badge, Button, Modal } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
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
          <p role="status" className="rounded-[var(--radius)] bg-ok-soft px-3.5 py-2.5 text-[0.875rem] text-ok">
            Invitation sent to {sent}.
          </p>
        )}
        <Field label="Email">{(id) => <TextInput id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required />}</Field>
        <Field label="Expires after">{(id) => <NumberInput id={id} value={days} min={1} max={365} nullable onValue={setDays} unit="days" />}</Field>
        <CheckList legend="Roles" options={(roles.data ?? []).map((r) => ({ value: r.id, label: roleName(r), hint: r.description ?? undefined }))} value={roleIds} onChange={setRoleIds} />
        <CheckList legend="Groups" options={(groups.data ?? []).map((g) => ({ value: g.id, label: g.name }))} value={groupIds} onChange={setGroupIds} />
        {invite.isError && (
          <p role="alert" className="text-[0.875rem] text-danger">
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
  if (list.isPending) return <Spinner label="Loading invitations…" />;
  if (list.isError)
    return (
      <p role="alert" className="text-[0.9rem] text-danger">
        {list.error.message}
      </p>
    );
  const writer = can("ridm:invitations:write");
  const err = resend.error ?? revoke.error;
  return (
    <div className="rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
      {err && (
        <p role="alert" className="px-4 pt-3 text-[0.875rem] text-danger">
          {err.message}
        </p>
      )}
      <table className="w-full text-[0.875rem]">
        <thead className="text-[0.75rem] uppercase tracking-wide text-muted">
          <tr className="border-b border-line">
            <th scope="col" className="px-4 py-2.5 text-start font-medium">Email</th>
            <th scope="col" className="px-4 py-2.5 text-start font-medium">Sent</th>
            <th scope="col" className="px-4 py-2.5 text-start font-medium">Expires</th>
            <th scope="col" className="px-4 py-2.5 text-start font-medium">Roles / groups</th>
            <th scope="col" className="px-4 py-2.5 text-end font-medium"><span className="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {list.data.length === 0 && (
            <tr>
              <td colSpan={5} className="px-4 py-8 text-center text-muted">No open invitations.</td>
            </tr>
          )}
          {list.data.map((i) => (
            <tr key={i.id} className="border-b border-line last:border-b-0">
              <td className="px-4 py-2.5 font-medium text-ink">{i.email}</td>
              <td className="px-4 py-2.5 text-muted">{formatDate("en", i.created_at)}</td>
              <td className="px-4 py-2.5 text-muted">{new Date(i.expires_at) < new Date() ? <Badge tone="danger">Expired</Badge> : formatDate("en", i.expires_at)}</td>
              <td className="px-4 py-2.5 text-muted">
                {i.roles.length} / {i.groups.length}
              </td>
              <td className="px-4 py-2.5 text-end">
                {writer && (
                  <span className="inline-flex gap-1.5">
                    <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={resend.isPending} onClick={() => resend.mutate(i.id)}>
                      Resend
                    </Button>
                    <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate(i.id)}>
                      Revoke
                    </Button>
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
