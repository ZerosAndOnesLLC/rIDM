"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Field, SaveIndicator, Section, SelectInput, TextArea, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { MAPPER_TYPES, defaultMapper, href, type ClaimMapperRow, type MapperConfig, type MapperType } from "@/lib/console/access";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useClientNames } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { CheckList } from "../clients/pickers";
import { JsonInput } from "../users/attributes";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "./common";

export function MappersPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { client, can } = useConsole();
  const names = useClientNames(tenant);
  const mappers = useQuery({
    queryKey: ["mappers", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/claim-mappers", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [creating, setCreating] = useState(false);
  const rows = [...(mappers.data ?? [])].sort((a, b) => (a.client_id ?? "").localeCompare(b.client_id ?? "") || a.name.localeCompare(b.name));
  return (
    <>
      <PageHeader
        title="Claim mappers"
        sub="Extra claims in access tokens, ID tokens and userinfo, tenant-wide or per client."
        actions={
          can("ridm:mappers:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New mapper
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Mappers">
            {mappers.isPending ? (
              <Spinner label="Loading…" />
            ) : mappers.isError ? (
              <ErrorLine error={mappers.error} />
            ) : rows.length === 0 ? (
              <p className="text-[0.875rem] text-muted">No mappers yet.</p>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {rows.map((m) => (
                  <li key={m.id}>
                    <Link
                      href={href("claim-mappers", tenant, { mapper: m.id })}
                      aria-current={m.id === selected ? "page" : undefined}
                      className={`flex items-center justify-between gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${m.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate">{m.name}</span>
                        <span className="block truncate text-[0.75rem] text-muted">{m.client_id ? (names.data?.[m.client_id] ?? "one client") : "tenant-wide"} · {(m.config as MapperConfig | null)?.type}</span>
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        }
        detail={selected ? <MapperView key={selected} tenant={tenant} id={selected} clientNames={names.data ?? {}} /> : <p className="text-[0.9rem] text-muted">Choose a mapper.</p>}
      />
      <CreateMapper tenant={tenant} open={creating} onOpenChange={setCreating} clientNames={names.data ?? {}} />
    </>
  );
}

function CreateMapper({ tenant, open, onOpenChange, clientNames }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void; clientNames: Record<string, string> }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [clientId, setClientId] = useState("");
  const [config, setConfig] = useState<MapperConfig>(defaultMapper("user_attribute"));
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/claim-mappers", { params: { path: { slug: tenant } }, body: { name: name.trim(), client_id: clientId || null, config } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (m) => {
      void qc.invalidateQueries({ queryKey: ["mappers", tenant] });
      setName("");
      onOpenChange(false);
      router.push(href("claim-mappers", tenant, { mapper: m.id }));
    },
  });
  return (
    <CreateDialog open={open} onOpenChange={onOpenChange} title="New claim mapper" submitLabel="Create mapper" pending={create.isPending} error={create.error?.message ?? null} onSubmit={() => name.trim() && create.mutate()}>
      <Field label="Name">{(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus required placeholder="department" />}</Field>
      <Field label="Applies to" hint="Cannot change later.">
        {(id, by) => (
          <SelectInput id={id} aria-describedby={by} value={clientId} onChange={(e) => setClientId(e.target.value)}>
            <option value="">Every client of the tenant</option>
            {Object.entries(clientNames)
              .sort((a, b) => a[1].localeCompare(b[1]))
              .map(([cid, n]) => (
                <option key={cid} value={cid}>
                  {n}
                </option>
              ))}
          </SelectInput>
        )}
      </Field>
      <Field label="Kind">
        {(id) => (
          <SelectInput id={id} value={config.type} onChange={(e) => setConfig(defaultMapper(e.target.value as MapperType))}>
            {MAPPER_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </SelectInput>
        )}
      </Field>
      <MapperFields config={config} onChange={setConfig} editable />
    </CreateDialog>
  );
}

/** The type-specific fields plus where the claim goes. */
function MapperFields({ config, onChange, editable }: { config: MapperConfig; onChange: (c: MapperConfig) => void; editable: boolean }) {
  const set = (patch: Partial<MapperConfig>) => onChange({ ...config, ...patch });
  const claim = (
    <Field label="Claim name" hint="Reserved claims (iss, sub, aud, exp, …) cannot be set.">
      {(id, by) => <TextInput id={id} aria-describedby={by} value={config.claim ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ claim: e.target.value })} />}
    </Field>
  );
  return (
    <>
      <p className="text-[0.8125rem] text-muted">{MAPPER_TYPES.find((t) => t.value === config.type)?.blurb}</p>
      {config.type === "user_attribute" && (
        <>
          <Field label="Source" hint="A user field (username, email, phone, locale) or attributes.<name>.">
            {(id, by) => <TextInput id={id} aria-describedby={by} value={config.attribute ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ attribute: e.target.value })} />}
          </Field>
          {claim}
          <Field label="Value type">
            {(id) => (
              <SelectInput id={id} value={config.json_type ?? "string"} disabled={!editable} onChange={(e) => set({ json_type: e.target.value as MapperConfig["json_type"] })}>
                <option value="string">String</option>
                <option value="number">Number</option>
                <option value="boolean">Boolean</option>
                <option value="json">JSON as stored</option>
              </SelectInput>
            )}
          </Field>
        </>
      )}
      {config.type === "groups" && (
        <>
          {claim}
          <Toggle label="Full paths" hint="parent/child instead of bare names." checked={config.full_path ?? false} disabled={!editable} onChange={(v) => set({ full_path: v })} />
        </>
      )}
      {config.type === "roles" && (
        <>
          {claim}
          <Field label="Client roles of" hint="Public client ID; empty means realm roles.">
            {(id, by) => <TextInput id={id} aria-describedby={by} value={config.client_id ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ client_id: e.target.value || null })} />}
          </Field>
        </>
      )}
      {config.type === "hardcoded" && (
        <>
          {claim}
          <Field label="Value" hint="JSON: a string in quotes, a number, true/false, or an object.">
            {(id, by) => <JsonInput id={id} describedBy={by} value={config.value} disabled={!editable} onChange={(v) => set({ value: v })} />}
          </Field>
        </>
      )}
      {config.type === "template" && (
        <>
          {claim}
          <Field label="Template" hint="Handlebars over user, tenant, client, roles and groups; must compile.">
            {(id, by) => <TextArea id={id} aria-describedby={by} value={config.template ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ template: e.target.value })} />}
          </Field>
        </>
      )}
      {config.type === "audience" && (
        <Field label="Audience" hint="Added to the access token's aud.">
          {(id, by) => <TextInput id={id} aria-describedby={by} value={config.audience ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ audience: e.target.value })} />}
        </Field>
      )}
      <CheckList
        legend="Include in"
        options={config.type === "audience" ? [{ value: "access", label: "Access token" }] : [{ value: "access", label: "Access token" }, { value: "id", label: "ID token" }, { value: "userinfo", label: "userinfo" }]}
        value={config.include_in}
        onChange={(v) => set({ include_in: v as MapperConfig["include_in"] })}
        disabled={!editable}
      />
    </>
  );
}

function MapperView({ tenant, id, clientNames }: { tenant: string; id: string; clientNames: Record<string, string> }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const query = useQuery({
    queryKey: ["mapper", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/claim-mappers/{mapper}", { params: { path: { slug: tenant, mapper: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<ClaimMapperRow | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const editable = can("ridm:mappers:write");
  const save = useCallback(
    async (patch: { name?: string; config?: unknown }, { keepalive }: SaveOptions) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/claim-mappers/{mapper}", { params: { path: { slug: tenant, mapper: id } }, body: patch as never, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["mapper", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["mapper", tenant, id], data);
      void qc.invalidateQueries({ queryKey: ["mappers", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save, { baseline: query.data });
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/claim-mappers/{mapper}", { params: { path: { slug: tenant, mapper: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["mappers", tenant] });
      router.push(href("claim-mappers", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading…" />;
  const config = (draft.config ?? defaultMapper("hardcoded")) as MapperConfig;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">
          {draft.name} <Badge>{draft.client_id ? (clientNames[draft.client_id] ?? "one client") : "tenant-wide"}</Badge>
        </h2>
        <SaveIndicator status={status} error={error} />
      </div>
      <Section id="mapper" title="Mapper" description="Changes reach new tokens at once.">
        <Field label="Name" wide>
          {(fid) => (
            <TextInput
              id={fid}
              value={draft.name}
              disabled={!editable}
              onChange={(e) => {
                setDraft({ ...draft, name: e.target.value });
                if (editable) queue({ name: e.target.value });
              }}
            />
          )}
        </Field>
        <div className="flex flex-col gap-4 sm:col-span-2">
          <MapperFields
            config={config}
            editable={editable}
            onChange={(c) => {
              setDraft({ ...draft, config: c });
              if (editable) queue({ config: c });
            }}
          />
        </div>
      </Section>
      {editable && <DeleteButton what="mapper" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description="The claim disappears from tokens issued from now on." />}
    </div>
  );
}
