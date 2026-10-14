"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/base/confirm-dialog";
import { DataTable, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { useToast } from "@/components/base/toast";
import { TextArea, TextInput } from "@/components/console/form";
import { Badge, Button, IconButton, PageHeader } from "@/components/console/ui";
import type { MtlsTrustAnchor } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

const DAY = 24 * 60 * 60 * 1000;

/** The certificate authorities `tls_client_auth` clients may present certificates from (RFC 8705). */
export function ClientCertificatesPage({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const { toast } = useToast();
  const editable = can("ridm:tenants:write");
  const anchors = useQuery({
    queryKey: ["mtls-trust-anchors", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/mtls/trust-anchors", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      // Expiry is judged against when the list was read, not on every render.
      return { anchors: data, now: Date.now() };
    },
  });
  const [name, setName] = useState("");
  const [pem, setPem] = useState("");
  const [removing, setRemoving] = useState<MtlsTrustAnchor | null>(null);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["mtls-trust-anchors", tenant] });
  const add = useMutation({
    mutationFn: async () => {
      const { error } = await client.POST("/admin/tenants/{slug}/mtls/trust-anchors", { params: { path: { slug: tenant } }, body: { name: name.trim(), certificate_pem: pem.trim() } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setName("");
      setPem("");
      invalidate();
    },
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/mtls/trust-anchors/{anchor}", { params: { path: { slug: tenant, anchor: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: invalidate,
  });
  const now = anchors.data?.now ?? 0;

  const columns: Column<MtlsTrustAnchor>[] = [
    { key: "name", header: "Name", width: "minmax(9rem, 1fr)", cell: (a) => <span className="truncate text-ink">{a.name}</span> },
    { key: "subject", header: "Subject", width: "minmax(12rem, 2fr)", cell: (a) => <span className="break-words font-mono text-small text-muted">{a.subject}</span> },
    { key: "expires", header: "Expires", width: "9rem", cell: (a) => <Expiry notAfter={a.not_after} now={now} /> },
    {
      key: "fingerprint",
      header: "SHA-256 thumbprint",
      width: "9rem",
      cell: (a) => (
        <span className="font-mono text-caption text-muted" title={a.fingerprint}>
          {a.fingerprint.slice(0, 16)}…
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      hideHeader: true,
      width: "2.5rem",
      align: "end",
      cell: (a) =>
        editable ? (
          <IconButton label={`Remove ${a.name}`} onClick={() => setRemoving(a)} className="text-danger hover:bg-danger-soft">
            <Trash2 className="size-4" aria-hidden />
          </IconButton>
        ) : null,
    },
  ];

  return (
    <>
      <PageHeader
        title="Client certificates"
        sub="Certificate authorities whose certificates clients may authenticate with (mutual TLS, tls_client_auth). A client certificate must chain to one of these, be valid now and allow client authentication; which client it authenticates is set on the client, by subject DN or subject alternative name."
      />
      <ErrorLine error={add.error} />
      {anchors.isError ? (
        <ErrorLine error={anchors.error} />
      ) : (
        <DataTable
          label="Certificate authorities"
          columns={columns}
          rows={anchors.data?.anchors ?? []}
          rowKey={(a) => a.id}
          loading={anchors.isPending}
          minWidth="42rem"
          empty={<EmptyState icon={BadgeCheck} title="No certificate authorities yet" description="Until one is added, no tls_client_auth client can authenticate." />}
        />
      )}
      {editable && !anchors.isPending && (
        <form
          className="mt-3 flex flex-col gap-2 rounded-[var(--radius)] border border-line bg-paper p-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim() && pem.trim()) add.mutate();
          }}
        >
          <TextInput aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Partner issuing CA" className="max-w-[20rem]" />
          <TextArea aria-label="CA certificate (PEM)" value={pem} onChange={(e) => setPem(e.target.value)} placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"} rows={6} spellCheck={false} className="font-mono text-small" />
          <div>
            <Button type="submit" variant="primary" disabled={!name.trim() || !pem.trim() || add.isPending}>
              <Plus className="size-4" aria-hidden />
              Add certificate authority
            </Button>
          </div>
        </form>
      )}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={`Remove ${removing?.name ?? ""}?`}
        description="Clients whose certificates chain only to this authority stop authenticating at once."
        confirmLabel="Remove"
        onConfirm={async () => {
          if (!removing) return;
          await remove.mutateAsync(removing.id);
          toast({ title: "Certificate authority removed", description: removing.name });
        }}
      />
    </>
  );
}

function Expiry({ notAfter, now }: { notAfter: string; now: number }) {
  const at = new Date(notAfter);
  const left = at.getTime() - now;
  const label = at.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  if (left <= 0) return <Badge tone="danger">Expired {label}</Badge>;
  if (left < 30 * DAY) return <Badge tone="accent">Expires {label}</Badge>;
  return <span className="text-muted">{label}</span>;
}
