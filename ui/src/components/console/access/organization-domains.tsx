"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck } from "lucide-react";
import { useState } from "react";
import { TextInput } from "@/components/console/form";
import { Badge, Button, Card } from "@/components/console/ui";
import { useConsole } from "@/lib/console/session";
import { challengeRecord, type OrganizationDomain } from "@/lib/console/organizations";
import { ErrorLine } from "./common";

export function OrganizationDomains({
  tenant,
  id,
  domains,
  editable,
  onChanged,
}: {
  tenant: string;
  id: string;
  domains: OrganizationDomain[];
  editable: boolean;
  onChanged: () => void;
}) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const done = async () => {
    setDomain("");
    // The domains come with the organization; nothing else changed.
    await qc.invalidateQueries({ queryKey: ["organization", tenant, id], exact: true });
    onChanged();
  };
  const add = useMutation({
    mutationFn: async () => {
      const { error } = await client.POST("/admin/tenants/{slug}/organizations/{org}/domains", {
        params: { path: { slug: tenant, org: id } },
        body: { domain: domain.trim(), auto_join: true },
      });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  const verify = useMutation({
    mutationFn: async (domainId: string) => {
      const { error } = await client.POST(
        "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}/verify",
        { params: { path: { slug: tenant, org: id, domain_id: domainId } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  const toggle = useMutation({
    mutationFn: async (v: { domainId: string; auto_join: boolean }) => {
      const { error } = await client.PATCH(
        "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}",
        {
          params: { path: { slug: tenant, org: id, domain_id: v.domainId } },
          body: { auto_join: v.auto_join },
        },
      );
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: async (domainId: string) => {
      const { error } = await client.DELETE(
        "/admin/tenants/{slug}/organizations/{org}/domains/{domain_id}",
        { params: { path: { slug: tenant, org: id, domain_id: domainId } } },
      );
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: done,
  });
  return (
    <Card title="Email domains">
      {domains.length === 0 && (
        <p className="text-[0.875rem] text-muted">
          No domains. A verified domain with auto-join makes everyone with a verified address there
          a member.
        </p>
      )}
      <ul className="divide-y divide-line">
        {domains.map((d) => (
          <li key={d.id} className="flex flex-col gap-2 py-3 text-[0.875rem]">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="flex items-center gap-2 font-medium text-ink">
                {d.domain}
                {d.verified_at ? (
                  <Badge>
                    <BadgeCheck className="size-3.5" aria-hidden /> verified
                  </Badge>
                ) : (
                  <Badge>unverified</Badge>
                )}
                {d.auto_join && <Badge>auto-join</Badge>}
              </span>
              {editable && (
                <span className="flex gap-2">
                  {!d.verified_at && (
                    <Button
                      className="min-h-8 px-2.5 text-[0.8125rem]"
                      disabled={verify.isPending}
                      onClick={() => verify.mutate(d.id)}
                    >
                      Check record
                    </Button>
                  )}
                  <Button
                    className="min-h-8 px-2.5 text-[0.8125rem]"
                    disabled={toggle.isPending}
                    onClick={() => toggle.mutate({ domainId: d.id, auto_join: !d.auto_join })}
                  >
                    {d.auto_join ? "Turn auto-join off" : "Turn auto-join on"}
                  </Button>
                  <Button
                    variant="danger"
                    className="min-h-8 px-2.5 text-[0.8125rem]"
                    disabled={remove.isPending}
                    onClick={() => remove.mutate(d.id)}
                  >
                    Remove
                  </Button>
                </span>
              )}
            </div>
            {!d.verified_at && (
              <p className="text-[0.8125rem] text-muted">
                Publish a TXT record at <code className="text-ink">{challengeRecord(d)}</code> with
                the value <code className="text-ink">{d.verification}</code>, then check it.
              </p>
            )}
          </li>
        ))}
      </ul>
      {editable && (
        <form
          className="mt-3 flex gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (domain.trim()) add.mutate();
          }}
        >
          <TextInput
            aria-label="Domain to add"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <Button type="submit" variant="primary" disabled={!domain.trim() || add.isPending}>
            Add
          </Button>
        </form>
      )}
      <ErrorLine error={add.error ?? verify.error ?? toggle.error ?? remove.error} />
    </Card>
  );
}
