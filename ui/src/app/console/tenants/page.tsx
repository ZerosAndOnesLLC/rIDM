"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Settings2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Field, TextInput } from "@/components/console/form";
import { Badge, Button, Modal, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useConsole } from "@/lib/console/session";
import { isValidSlug } from "@/lib/console/settings";
import { useConsoleTenant } from "@/lib/console/tenant";

/** Every tenant a global administrator reaches (or the caller's own), plus creation. */
export default function TenantsPage() {
  const { client, can, me } = useConsole();
  const current = useConsoleTenant();
  const [filter, setFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const tenants = useQuery({
    queryKey: ["tenants", "all"],
    queryFn: async () => {
      const out: { id: string; slug: string; display_name: string; status: string; created_at: string }[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 20; page += 1) {
        const { data, error } = await client.GET("/admin/tenants", { params: { query: { limit: 100, cursor } } });
        if (error) throw new Error(error.detail ?? error.title);
        out.push(...data.items);
        if (!data.next_cursor) break;
        cursor = data.next_cursor;
      }
      return out;
    },
  });
  const q = filter.trim().toLowerCase();
  const rows = (tenants.data ?? []).filter((t) => !q || t.slug.includes(q) || t.display_name.toLowerCase().includes(q));
  const canCreate = me?.scope === "global" && can("ridm:tenants:create");

  return (
    <>
      <PageHeader
        title="Tenants"
        sub={me?.scope === "global" ? "Every tenant on this server." : "Your tenant."}
        actions={
          canCreate ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New tenant
            </Button>
          ) : undefined
        }
      />
      <div className="mb-4 max-w-sm">
        <TextInput aria-label="Filter tenants" placeholder="Filter by slug or name…" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      {tenants.isError ? (
        <p role="alert" className="text-[0.9rem] text-danger">
          {tenants.error.message}
        </p>
      ) : tenants.isPending ? (
        <Spinner label="Loading tenants…" />
      ) : (
        <div className="overflow-x-auto rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
          <table className="w-full text-[0.875rem]">
            <thead className="text-start text-[0.75rem] uppercase tracking-wide text-muted">
              <tr className="border-b border-line">
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Tenant</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Slug</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Status</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Created</th>
                <th scope="col" className="px-4 py-2.5 text-end font-medium"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted">No tenant matches.</td>
                </tr>
              )}
              {rows.map((t) => (
                <tr key={t.id} className="border-b border-line last:border-b-0 hover:bg-ground/60">
                  <td className="px-4 py-2.5 font-medium text-ink">
                    {t.display_name}
                    {t.slug === current && <span className="ms-2 text-[0.75rem] font-normal text-muted">current</span>}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[0.8125rem] text-muted">{t.slug}</td>
                  <td className="px-4 py-2.5">{t.status === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="danger">Disabled</Badge>}</td>
                  <td className="px-4 py-2.5 text-muted">{formatDate("en", t.created_at, { dateStyle: "medium" })}</td>
                  <td className="px-4 py-2.5 text-end">
                    <Link href={`/console/settings/?tenant=${encodeURIComponent(t.slug)}`} className="inline-flex items-center gap-1.5 rounded-[var(--radius)] px-2.5 py-1.5 text-link hover:bg-ground">
                      <Settings2 className="size-4" aria-hidden />
                      Settings
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {canCreate && <CreateTenant open={creating} onOpenChange={setCreating} />}
    </>
  );
}

function CreateTenant({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants", { body: { slug: slug.trim(), display_name: name.trim() } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (t) => {
      void qc.invalidateQueries({ queryKey: ["tenants"] });
      onOpenChange(false);
      router.push(`/console/settings/?tenant=${encodeURIComponent(t.slug)}`);
    },
  });
  const slugError = touched && !isValidSlug(slug.trim()) ? "1–63 lowercase letters, digits or hyphens, not starting or ending with a hyphen." : null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!isValidSlug(slug.trim()) || !name.trim()) return;
    create.mutate();
  };
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="New tenant" description="A tenant has its own users, clients, keys and issuer URL.">
      <form onSubmit={submit} className="flex flex-col gap-4 px-5 pb-5 pt-3" noValidate>
        <Field label="Display name">
          {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" autoFocus required />}
        </Field>
        <Field label="Slug" hint="Part of the issuer URL: /t/<slug>. Cannot change later." error={slugError}>
          {(id, by) => (
            <TextInput
              id={id}
              aria-describedby={by}
              aria-invalid={slugError ? true : undefined}
              value={slug}
              onChange={(e) => setSlug(e.target.value.toLowerCase())}
              onBlur={() => setTouched(true)}
              placeholder="acme"
              autoCapitalize="none"
              spellCheck={false}
              required
            />
          )}
        </Field>
        {create.isError && (
          <p role="alert" className="text-[0.875rem] text-danger">
            {create.error.message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create tenant"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
