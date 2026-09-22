"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { TextArea, TextInput } from "@/components/console/form";
import { Badge, Button, IconButton, Modal, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import type { MtlsTrustAnchor } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

const DAY = 24 * 60 * 60 * 1000;

/** The certificate authorities `tls_client_auth` clients may present certificates from (RFC 8705). */
export function ClientCertificatesPage({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
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
    onSuccess: () => {
      setRemoving(null);
      invalidate();
    },
  });
  return (
    <>
      <PageHeader
        title="Client certificates"
        sub="Certificate authorities whose certificates clients may authenticate with (mutual TLS, tls_client_auth). A client certificate must chain to one of these, be valid now and allow client authentication; which client it authenticates is set on the client, by subject DN or subject alternative name."
      />
      <ErrorLine error={add.error} />
      {anchors.isPending ? (
        <Spinner label="Loading…" />
      ) : anchors.isError ? (
        <ErrorLine error={anchors.error} />
      ) : (
        <div className="overflow-x-auto rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
          <table className="w-full text-[0.875rem]">
            <thead className="text-[0.75rem] uppercase tracking-wide text-muted">
              <tr className="border-b border-line">
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Name</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Subject</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Expires</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">SHA-256 thumbprint</th>
                <th scope="col" className="px-4 py-2.5 text-end font-medium"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {anchors.data.anchors.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted">No certificate authorities yet. Until one is added, no tls_client_auth client can authenticate.</td>
                </tr>
              )}
              {anchors.data.anchors.map((a) => (
                <tr key={a.id} className="border-b border-line last:border-b-0">
                  <td className="px-4 py-2 text-ink">{a.name}</td>
                  <td className="max-w-[22rem] break-words px-4 py-2 font-mono text-[0.8125rem] text-muted">{a.subject}</td>
                  <td className="whitespace-nowrap px-4 py-2">
                    <Expiry notAfter={a.not_after} now={anchors.data.now} />
                  </td>
                  <td className="px-4 py-2 font-mono text-[0.75rem] text-muted" title={a.fingerprint}>
                    {a.fingerprint.slice(0, 16)}…
                  </td>
                  <td className="px-4 py-2 text-end">
                    {editable && (
                      <IconButton label={`Remove ${a.name}`} onClick={() => setRemoving(a)} className="text-danger hover:bg-danger-soft">
                        <Trash2 className="size-4" aria-hidden />
                      </IconButton>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {editable && (
            <form
              className="flex flex-col gap-2 border-t border-line p-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (name.trim() && pem.trim()) add.mutate();
              }}
            >
              <TextInput aria-label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Partner issuing CA" className="max-w-[20rem]" />
              <TextArea aria-label="CA certificate (PEM)" value={pem} onChange={(e) => setPem(e.target.value)} placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"} rows={6} spellCheck={false} className="font-mono text-[0.8125rem]" />
              <div>
                <Button type="submit" variant="primary" disabled={!name.trim() || !pem.trim() || add.isPending}>
                  <Plus className="size-4" aria-hidden />
                  Add certificate authority
                </Button>
              </div>
            </form>
          )}
        </div>
      )}
      <Modal open={removing !== null} onOpenChange={(o) => !o && setRemoving(null)} title={`Remove ${removing?.name ?? ""}?`} description="Clients whose certificates chain only to this authority stop authenticating at once.">
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <ErrorLine error={remove.error} />
          <div className="flex justify-end gap-2">
            <Button onClick={() => setRemoving(null)}>Cancel</Button>
            <Button variant="danger" disabled={remove.isPending} onClick={() => removing && remove.mutate(removing.id)}>
              {remove.isPending ? "Removing…" : "Remove"}
            </Button>
          </div>
        </div>
      </Modal>
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
