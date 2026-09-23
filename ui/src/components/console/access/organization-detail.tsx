"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Field, SaveIndicator, Section, SelectInput, TextInput } from "@/components/console/form";
import { Spinner } from "@/components/ui";
import { href } from "@/lib/console/access";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useConsole } from "@/lib/console/session";
import { type OrganizationDetail } from "@/lib/console/organizations";
import { DeleteButton, ErrorLine } from "./common";
import { OrganizationDomains } from "./organization-domains";
import { OrganizationInvitations, OrganizationMembers } from "./organization-members";
import { OrganizationRoles } from "./organization-roles";

export const P_WRITE = "ridm:orgs:write";

export function OrganizationDetailView({ tenant, id }: { tenant: string; id: string }) {
  const { client, can, canInOrg, confinedToOrg, org } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  // Inside their own organization an org administrator writes as a tenant
  // administrator does — except for the three things the tenant keeps.
  const ownOrg = org?.id === id;
  const editable = can(P_WRITE) || (ownOrg && canInOrg(P_WRITE));
  const confined = ownOrg && confinedToOrg(P_WRITE);
  const query = useQuery({
    queryKey: ["organization", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: id } },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<OrganizationDetail | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const save = useCallback(
    async (
      patch: { slug?: string; display_name?: string; description?: string | null; status?: string },
      { keepalive }: SaveOptions,
    ) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: id } },
        body: patch as never,
        keepalive,
      });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["organization", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["organization", tenant, id], (old: OrganizationDetail | undefined) =>
        old ? { ...old, ...data } : old,
      );
      void qc.invalidateQueries({ queryKey: ["organizations", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save);
  const update = (patch: Partial<OrganizationDetail>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (editable) queue(patch);
  };
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/organizations/{org}", {
        params: { path: { slug: tenant, org: id } },
      });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["organizations", tenant] });
      router.push(href("organizations", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading organization…" />;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">{draft.display_name}</h2>
        <SaveIndicator status={status} error={error} />
      </div>
      <Section
        id="organization"
        title="Organization"
        description={`${draft.member_count} member${draft.member_count === 1 ? "" : "s"}.`}
      >
        <Field label="Name">
          {(fid) => (
            <TextInput
              id={fid}
              value={draft.display_name}
              disabled={!editable}
              onChange={(e) => update({ display_name: e.target.value })}
            />
          )}
        </Field>
        <Field label="Slug" hint={confined ? "The tenant's administrators change this." : undefined}>
          {(fid, by) => (
            <TextInput
              id={fid}
              aria-describedby={by}
              value={draft.slug}
              disabled={!editable || confined}
              onChange={(e) => update({ slug: e.target.value })}
            />
          )}
        </Field>
        <Field label="Status" hint="A disabled organization takes no new members and cannot be signed in to.">
          {(fid, by) => (
            <SelectInput
              id={fid}
              aria-describedby={by}
              value={draft.status}
              disabled={!editable || confined}
              onChange={(e) => update({ status: e.target.value as OrganizationDetail["status"] })}
            >
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </SelectInput>
          )}
        </Field>
        <Field label="Description" wide>
          {(fid) => (
            <TextInput
              id={fid}
              value={draft.description ?? ""}
              disabled={!editable}
              onChange={(e) => update({ description: e.target.value || null })}
            />
          )}
        </Field>
      </Section>
      <OrganizationMembers tenant={tenant} id={id} editable={editable} confined={confined} />
      <OrganizationInvitations tenant={tenant} id={id} />
      <OrganizationDomains
        tenant={tenant}
        id={id}
        domains={draft.domains}
        editable={editable}
        onChanged={() => setResetCount((n) => n + 1)}
      />
      <OrganizationRoles tenant={tenant} id={id} editable={editable} />
      {editable && !confined && (
        <DeleteButton
          what="organization"
          pending={del.isPending}
          error={del.error?.message ?? null}
          onConfirm={() => del.mutate()}
          description="Members keep their accounts but lose this membership, its domains and every role granted inside it."
        />
      )}
    </div>
  );
}
