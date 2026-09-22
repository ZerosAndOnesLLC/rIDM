"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, KeyRound, Plus, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState, type ChangeEvent } from "react";
import { Field, NumberInput, SaveIndicator, Section, SelectInput, TagsInput, TextArea, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, IconButton, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { href, type SamlAttribute, type SamlIdp, type SamlKey, type SamlSp, type SamlSpInput } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "../access/common";
import { CopyButton } from "../clients/reveal";

const NAME_ID_FORMATS: { value: NonNullable<SamlSpInput["name_id_format"]>; label: string; hint: string }[] = [
  { value: "persistent", label: "Persistent", hint: "Opaque and stable, different for every service provider." },
  { value: "transient", label: "Transient", hint: "Opaque and new on every sign-in." },
  { value: "email", label: "Email address", hint: "The user's email; users without one cannot sign in." },
  { value: "unspecified", label: "User id", hint: "The user's id in rIDM." },
];

const KEY_TONE: Record<SamlKey["status"], "ok" | "accent" | "neutral"> = { active: "ok", pending: "accent", retiring: "neutral" };

type ApiError = { detail?: string | null; title?: string; errors?: { field: string; message: string }[] | null };

function message(error: ApiError): string {
  return error.errors?.map((e) => `${e.field} ${e.message}`).join("; ") || error.detail || error.title || "request failed";
}

/** The registration that reproduces a stored SP (`saml_sps::to_input`). */
function toInput(v: SamlSp): SamlSpInput {
  const { client: c, saml: s } = v;
  return {
    name: c.name,
    description: c.description ?? null,
    logo_uri: c.logo_uri ?? null,
    client_uri: c.client_uri ?? null,
    client_id: c.client_id,
    allowed_scopes: c.allowed_scopes,
    require_consent: c.require_consent,
    entity_id: s.entity_id,
    acs_urls: s.acs_urls,
    slo_url: s.slo_url ?? null,
    slo_binding: s.slo_binding,
    name_id_format: s.name_id_format,
    signing_certificates: s.signing_certificates,
    encryption_certificate: s.encryption_certificate ?? null,
    require_signed_requests: s.require_signed_requests,
    sign_response: s.sign_response,
    sign_assertion: s.sign_assertion,
    encrypt_assertion: s.encrypt_assertion,
    data_encryption: s.data_encryption,
    key_transport: s.key_transport,
    allow_idp_initiated: s.allow_idp_initiated,
    default_relay_state: s.default_relay_state ?? null,
    attributes: s.attributes,
    assertion_ttl_secs: s.assertion_ttl_secs,
  };
}

export function SamlPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { client, can } = useConsole();
  const [creating, setCreating] = useState(false);
  const list = useQuery({
    queryKey: ["saml-sps", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/saml/service-providers", { params: { path: { slug: tenant } } });
      if (error) throw new Error(message(error));
      return data;
    },
  });
  return (
    <>
      <PageHeader
        title="SAML"
        sub="rIDM as a SAML 2.0 identity provider, for applications that sign users in with SAML."
        actions={
          can("ridm:clients:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New service provider
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <div className="flex flex-col gap-4">
            <Card title="Service providers">
              {list.isPending ? (
                <Spinner label="Loading…" />
              ) : list.isError ? (
                <ErrorLine error={list.error} />
              ) : list.data.length === 0 ? (
                <p className="text-[0.875rem] text-muted">No service providers yet.</p>
              ) : (
                <ul className="flex flex-col gap-0.5">
                  {list.data.map((p) => (
                    <li key={p.client.id}>
                      <Link
                        href={href("saml", tenant, { sp: p.client.id })}
                        aria-current={p.client.id === selected ? "page" : undefined}
                        className={`flex items-center justify-between gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${p.client.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                      >
                        <span className="min-w-0">
                          <span className="block truncate">{p.client.name}</span>
                          <span className="block truncate text-[0.75rem] text-muted">{p.saml.entity_id}</span>
                        </span>
                        {p.client.status !== "active" && <Badge>off</Badge>}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        }
        detail={selected ? <SpView key={selected} tenant={tenant} id={selected} /> : <IdpView tenant={tenant} />}
      />
      <CreateSp tenant={tenant} open={creating} onOpenChange={setCreating} />
    </>
  );
}

function useIdp(tenant: string) {
  const { client } = useConsole();
  return useQuery({
    queryKey: ["saml-idp", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/saml", { params: { path: { slug: tenant } } });
      if (error) throw new Error(message(error));
      return data as SamlIdp;
    },
  });
}

/** A URL to hand over: stacked under its label, wrapping, with a copy button. */
function UrlRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1 py-2 not-last:border-b not-last:border-line">
      <dt className="text-[0.8125rem] text-muted">{label}</dt>
      <dd className="flex min-w-0 items-center gap-2">
        <code className="min-w-0 flex-1 break-all font-mono text-[0.8125rem] text-ink">{value}</code>
        <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} />
      </dd>
    </div>
  );
}

/** What to give a service provider, and the signing keys behind it. */
function IdpView({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const idp = useIdp(tenant);
  const act = useMutation({
    mutationFn: async (what: { add?: true; id?: string; op?: "activate" | "delete" }) => {
      const r = what.add
        ? await client.POST("/admin/tenants/{slug}/saml/keys", { params: { path: { slug: tenant } } })
        : what.op === "activate"
          ? await client.POST("/admin/tenants/{slug}/saml/keys/{key}/activate", { params: { path: { slug: tenant, key: what.id! } } })
          : await client.DELETE("/admin/tenants/{slug}/saml/keys/{key}", { params: { path: { slug: tenant, key: what.id! } } });
      if (r.error) throw new Error(message(r.error));
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["saml-idp", tenant] }),
  });
  if (idp.isPending) return <Spinner label="Loading…" />;
  if (idp.isError) return <ErrorLine error={idp.error} />;
  const d = idp.data;
  const editable = can("ridm:keys:write");
  const pending = d.keys.some((k) => k.status === "pending");
  return (
    <div className="flex flex-col gap-4">
      <Card
        title="Identity provider"
        actions={
          <a href={d.metadata_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[0.875rem] text-accent hover:underline underline-offset-4">
            <Download className="size-4" aria-hidden />
            Metadata
          </a>
        }
      >
        <p className="mb-3 text-[0.875rem] text-muted">Give service providers the metadata URL, or these values if they are entered by hand.</p>
        <dl className="flex flex-col">
          <UrlRow label="Entity ID" value={d.entity_id} />
          <UrlRow label="Single sign-on" value={d.sso_url} />
          <UrlRow label="Single logout" value={d.slo_url} />
          <UrlRow label="Metadata" value={d.metadata_url} />
        </dl>
      </Card>
      <Card
        title="Signing keys"
        actions={
          editable && !pending ? (
            <Button disabled={act.isPending} onClick={() => act.mutate({ add: true })}>
              <KeyRound className="size-4" aria-hidden />
              Start a rollover
            </Button>
          ) : undefined
        }
      >
        <p className="mb-3 text-[0.875rem] text-muted">
          Service providers pin these certificates, so they never change on their own. A rollover adds a pending key, published at once; activate it once every service provider has the new metadata, then delete the retired one.
        </p>
        <ul className="flex flex-col gap-3">
          {d.keys.map((k) => (
            <li key={k.id} className="flex flex-col gap-2 rounded-[var(--radius)] border border-line p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Badge tone={KEY_TONE[k.status]}>{k.status}</Badge>
                <span className="text-[0.8125rem] text-muted">
                  Valid until {formatDate("en", k.not_after, { dateStyle: "medium" })}
                  {k.activated_at ? ` · signing since ${formatDate("en", k.activated_at, { dateStyle: "medium" })}` : ""}
                </span>
              </div>
              <code className="break-all font-mono text-[0.75rem] text-muted" title="SHA-256 fingerprint">
                {k.sha256_fingerprint}
              </code>
              {editable && k.status !== "active" && (
                <div className="flex flex-wrap gap-2">
                  <Button variant="primary" disabled={act.isPending} onClick={() => act.mutate({ id: k.id, op: "activate" })}>
                    Activate
                  </Button>
                  <Button variant="danger" disabled={act.isPending} onClick={() => act.mutate({ id: k.id, op: "delete" })}>
                    Delete
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
        <ErrorLine error={act.error} />
      </Card>
    </div>
  );
}

function CreateSp({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [metadata, setMetadata] = useState("");
  const [draft, setDraft] = useState<SamlSpInput | null>(null);
  const [name, setName] = useState("");
  const [entity, setEntity] = useState("");
  const [acs, setAcs] = useState("");
  const read = useMutation({
    mutationFn: async (xml: string) => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/saml/service-providers/metadata", { params: { path: { slug: tenant } }, body: { metadata: xml } });
      if (error) throw new Error(message(error));
      return data as SamlSpInput;
    },
    onSuccess: (d) => {
      setDraft(d);
      setName(d.name);
      setEntity(d.entity_id);
      setAcs(d.acs_urls[0] ?? "");
    },
  });
  const create = useMutation({
    mutationFn: async () => {
      const base: SamlSpInput = draft ?? ({ acs_urls: [], signing_certificates: [] } as unknown as SamlSpInput);
      const acsUrls = draft ? [acs.trim(), ...draft.acs_urls.filter((u) => u !== acs.trim())] : [acs.trim()];
      const { data, error } = await client.POST("/admin/tenants/{slug}/saml/service-providers", {
        params: { path: { slug: tenant } },
        body: { ...base, name: name.trim(), entity_id: entity.trim(), acs_urls: acsUrls.filter(Boolean) },
      });
      if (error) throw new Error(message(error));
      return data as SamlSp;
    },
    onSuccess: (sp) => {
      void qc.invalidateQueries({ queryKey: ["saml-sps", tenant] });
      setMetadata("");
      setDraft(null);
      setName("");
      setEntity("");
      setAcs("");
      onOpenChange(false);
      router.push(href("saml", tenant, { sp: sp.client.id }));
    },
  });
  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    void file.text().then((text) => {
      setMetadata(text);
      read.mutate(text);
    });
  };
  return (
    <CreateDialog
      open={open}
      onOpenChange={onOpenChange}
      title="New service provider"
      description="Paste or upload the application's SAML metadata to fill everything in, or enter its entity ID and assertion consumer service URL."
      submitLabel="Create service provider"
      pending={create.isPending}
      error={(read.error ?? create.error)?.message ?? null}
      onSubmit={() => name.trim() && entity.trim() && acs.trim() && create.mutate()}
    >
      <Field label="Metadata" hint={draft ? "Read: review the values below." : "The SP's EntityDescriptor XML."}>
        {(id, by) => <TextArea id={id} aria-describedby={by} value={metadata} spellCheck={false} placeholder="<md:EntityDescriptor …>" onChange={(e) => setMetadata(e.target.value)} />}
      </Field>
      <div className="flex flex-wrap items-center gap-2">
        <Button disabled={!metadata.trim() || read.isPending} onClick={() => read.mutate(metadata)}>
          {read.isPending ? "Reading…" : "Read metadata"}
        </Button>
        <label className="inline-flex cursor-pointer items-center gap-2 text-[0.875rem] text-accent hover:underline underline-offset-4">
          <input type="file" accept=".xml,application/xml,text/xml,application/samlmetadata+xml" className="sr-only" onChange={onFile} />
          Upload a file
        </label>
      </div>
      <Field label="Name" hint="Shown on the sign-in and consent pages.">
        {(id, by) => <TextInput id={id} aria-describedby={by} value={name} onChange={(e) => setName(e.target.value)} required />}
      </Field>
      <Field label="Entity ID">{(id) => <TextInput id={id} value={entity} onChange={(e) => setEntity(e.target.value)} required spellCheck={false} placeholder="https://app.example.com/saml" />}</Field>
      <Field label="Assertion consumer service URL" hint="Where rIDM posts the signed response (HTTP-POST).">
        {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={acs} onChange={(e) => setAcs(e.target.value)} required spellCheck={false} placeholder="https://app.example.com/saml/acs" />}
      </Field>
    </CreateDialog>
  );
}

function AttributeRows({ value, disabled, onChange }: { value: SamlAttribute[]; disabled: boolean; onChange: (v: SamlAttribute[]) => void }) {
  const set = (i: number, patch: Partial<SamlAttribute>) => onChange(value.map((a, j) => (j === i ? { ...a, ...patch } : a)));
  return (
    <div className="sm:col-span-2 flex flex-col gap-2">
      <span className="text-[0.8125rem] font-medium text-ink">Attributes</span>
      <p className="text-[0.8125rem] text-muted">With no rows, every claim the allowed scopes release goes out under its own name. With rows, only these, under the names the service provider expects. `roles` and `groups` are available too.</p>
      {value.map((a, i) => (
        <div key={i} className="grid gap-2 rounded-[var(--radius)] border border-line p-2 sm:grid-cols-[1fr_1.5fr_8rem_auto]">
          <TextInput aria-label={`Claim ${i + 1}`} value={a.claim} disabled={disabled} spellCheck={false} placeholder="email" onChange={(e) => set(i, { claim: e.target.value })} />
          <TextInput aria-label={`Attribute name ${i + 1}`} value={a.name} disabled={disabled} spellCheck={false} placeholder="urn:oid:0.9.2342.19200300.100.1.3" onChange={(e) => set(i, { name: e.target.value })} />
          <SelectInput aria-label={`Name format ${i + 1}`} value={a.name_format ?? "basic"} disabled={disabled} onChange={(e) => set(i, { name_format: e.target.value as SamlAttribute["name_format"] })}>
            <option value="basic">basic</option>
            <option value="uri">uri</option>
            <option value="unspecified">unspecified</option>
          </SelectInput>
          <IconButton label={`Remove attribute ${i + 1}`} disabled={disabled} onClick={() => onChange(value.filter((_, j) => j !== i))}>
            <Trash2 className="size-4" aria-hidden />
          </IconButton>
        </div>
      ))}
      {!disabled && (
        <div>
          <Button onClick={() => onChange([...value, { claim: "", name: "", name_format: "basic" }])}>
            <Plus className="size-4" aria-hidden />
            Add attribute
          </Button>
        </div>
      )}
    </div>
  );
}

export function Certificates({
  value,
  disabled,
  onChange,
  label = "Request signing certificates",
  hint = "Signatures on the SP\u2019s requests are checked against these; list two during the SP\u2019s own key rollover.",
  empty = "None: signatures are not checked.",
}: {
  value: string[];
  disabled: boolean;
  onChange: (v: string[]) => void;
  label?: string;
  hint?: string;
  empty?: string;
}) {
  const [pem, setPem] = useState("");
  return (
    <div className="sm:col-span-2 flex flex-col gap-2">
      <span className="text-[0.8125rem] font-medium text-ink">{label}</span>
      <p className="text-[0.8125rem] text-muted">{hint}</p>
      {value.length === 0 && <p className="text-[0.8125rem] text-muted">{empty}</p>}
      {value.map((c, i) => (
        <div key={c} className="flex items-center gap-2 rounded-[var(--radius)] border border-line px-2 py-1.5">
          <code className="min-w-0 flex-1 truncate font-mono text-[0.75rem] text-muted">{c}</code>
          <IconButton label={`Remove certificate ${i + 1}`} disabled={disabled} onClick={() => onChange(value.filter((_, j) => j !== i))}>
            <Trash2 className="size-4" aria-hidden />
          </IconButton>
        </div>
      ))}
      {!disabled && (
        <div className="flex flex-col gap-2">
          <TextArea aria-label="Certificate to add (PEM or base64)" value={pem} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => setPem(e.target.value)} />
          <div>
            <Button
              disabled={!pem.trim()}
              onClick={() => {
                onChange([...value, pem.trim()]);
                setPem("");
              }}
            >
              Add certificate
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function SpView({ tenant, id }: { tenant: string; id: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const editable = can("ridm:clients:write");
  const idp = useIdp(tenant);
  const query = useQuery({
    queryKey: ["saml-sp", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/saml/service-providers/{sp}", { params: { path: { slug: tenant, sp: id } } });
      if (error) throw new Error(message(error));
      return data as SamlSp;
    },
  });
  const [draft, setDraft] = useState<SamlSpInput | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ? toInput(query.data) : null);
  }
  if (draft === null && query.data) setDraft(toInput(query.data));
  const save = useCallback(
    async (patch: Partial<SamlSpInput>, { keepalive }: SaveOptions) => {
      const stored = qc.getQueryData<SamlSp>(["saml-sp", tenant, id]);
      if (!stored) return;
      const body = { ...toInput(stored), ...patch };
      const { data, error } = await client.PUT("/admin/tenants/{slug}/saml/service-providers/{sp}", { params: { path: { slug: tenant, sp: id } }, body, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["saml-sp", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(message(error));
      }
      qc.setQueryData(["saml-sp", tenant, id], data);
      void qc.invalidateQueries({ queryKey: ["saml-sps", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save);
  const update = (patch: Partial<SamlSpInput>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (!editable) return;
    // A row being typed in stays on the page until it has both halves;
    // the API would refuse it, and the refusal reloads the form.
    if (patch.attributes) queue({ ...patch, attributes: patch.attributes.filter((a) => a.claim.trim() && a.name.trim()) });
    else queue(patch);
  };
  const setEnabled = useMutation({
    mutationFn: async (on: boolean) => {
      const { error } = await client.PATCH("/admin/tenants/{slug}/clients/{client}", { params: { path: { slug: tenant, client: id } }, body: { status: on ? "active" : "disabled" } as never });
      if (error) throw new Error(message(error));
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["saml-sp", tenant, id] });
      void qc.invalidateQueries({ queryKey: ["saml-sps", tenant] });
    },
  });
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/saml/service-providers/{sp}", { params: { path: { slug: tenant, sp: id } } });
      if (error) throw new Error(message(error));
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["saml-sps", tenant] });
      router.push(href("saml", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft || !query.data) return <Spinner label="Loading…" />;
  const active = query.data.client.status === "active";
  const initUrl = idp.data ? `${idp.data.init_url}?sp=${encodeURIComponent(query.data.client.client_id)}` : null;
  const nameIdHint = NAME_ID_FORMATS.find((f) => f.value === draft.name_id_format)?.hint;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">{draft.name}</h2>
        <SaveIndicator status={status} error={error} />
      </div>
      <Section id="saml-app" title="Application">
        <Field label="Name">{(fid) => <TextInput id={fid} value={draft.name} disabled={!editable} onChange={(e) => update({ name: e.target.value })} />}</Field>
        <Field label="Client ID" hint="rIDM's own id for it: audit, roles, consent.">
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={query.data.client.client_id} readOnly className="font-mono" />}
        </Field>
        <Field label="Description" wide>
          {(fid) => <TextInput id={fid} value={draft.description ?? ""} disabled={!editable} onChange={(e) => update({ description: e.target.value || null })} />}
        </Field>
        <div className="sm:col-span-2">
          <Toggle label="Enabled" hint="A disabled service provider gets no sign-in." checked={active} disabled={!editable || setEnabled.isPending} onChange={(v) => setEnabled.mutate(v)} />
          <ErrorLine error={setEnabled.error} />
        </div>
      </Section>
      <Section id="saml-endpoints" title="Service provider" description="From the SP's metadata or its SAML settings page.">
        <Field label="Entity ID" wide>
          {(fid) => <TextInput id={fid} value={draft.entity_id} disabled={!editable} spellCheck={false} onChange={(e) => update({ entity_id: e.target.value })} />}
        </Field>
        <Field label="Assertion consumer services" hint="HTTP-POST URLs; the first is the default, and a request may only name one of these." wide>
          {(fid, by) => <TagsInput id={fid} describedBy={by} value={draft.acs_urls} onChange={(v) => update({ acs_urls: v })} placeholder="https://app.example.com/saml/acs" />}
        </Field>
        <Field label="Single logout URL" hint="Leave empty if the SP has no logout service.">
          {(fid, by) => <TextInput id={fid} aria-describedby={by} type="url" value={draft.slo_url ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ slo_url: e.target.value || null })} />}
        </Field>
        <Field label="Logout binding">
          {(fid) => (
            <SelectInput id={fid} value={draft.slo_binding ?? "redirect"} disabled={!editable} onChange={(e) => update({ slo_binding: e.target.value as SamlSpInput["slo_binding"] })}>
              <option value="redirect">HTTP-Redirect</option>
              <option value="post">HTTP-POST</option>
            </SelectInput>
          )}
        </Field>
      </Section>
      <Section id="saml-subject" title="Subject and attributes">
        <Field label="NameID format" hint={nameIdHint}>
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={draft.name_id_format ?? "persistent"} disabled={!editable} onChange={(e) => update({ name_id_format: e.target.value as SamlSpInput["name_id_format"] })}>
              {NAME_ID_FORMATS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
        <Field label="Assertion lifetime" hint="How long the SP may accept the assertion.">
          {(fid, by) => <NumberInput id={fid} describedBy={by} value={draft.assertion_ttl_secs ?? 300} min={30} max={3600} unit="seconds" disabled={!editable} onValue={(v) => v !== null && update({ assertion_ttl_secs: v })} />}
        </Field>
        <Field label="Allowed scopes" hint="Their claims are what may be released as attributes." wide>
          {(fid, by) => <TagsInput id={fid} describedBy={by} value={draft.allowed_scopes ?? []} onChange={(v) => update({ allowed_scopes: v })} placeholder="openid, profile, email" />}
        </Field>
        <div className="sm:col-span-2">
          <Toggle label="Ask for consent" hint="Show the consent page before releasing attributes the first time." checked={draft.require_consent ?? false} disabled={!editable} onChange={(v) => update({ require_consent: v })} />
        </div>
        <AttributeRows value={draft.attributes ?? []} disabled={!editable} onChange={(v) => update({ attributes: v })} />
      </Section>
      <Section id="saml-security" title="Signatures and encryption">
        <div className="sm:col-span-2 flex flex-col gap-1">
          <Toggle label="Sign the response" checked={draft.sign_response ?? true} disabled={!editable} onChange={(v) => update({ sign_response: v })} />
          <Toggle label="Sign the assertion" hint="At least one of the two stays on." checked={draft.sign_assertion ?? true} disabled={!editable} onChange={(v) => update({ sign_assertion: v })} />
          <Toggle label="Require signed requests" hint="Refuse requests the SP did not sign with a certificate below." checked={draft.require_signed_requests ?? false} disabled={!editable} onChange={(v) => update({ require_signed_requests: v })} />
        </div>
        <Certificates value={draft.signing_certificates} disabled={!editable} onChange={(v) => update({ signing_certificates: v })} />
        <div className="sm:col-span-2">
          <Toggle label="Encrypt the assertion" hint="Only the SP's private key can read it." checked={draft.encrypt_assertion ?? false} disabled={!editable} onChange={(v) => update({ encrypt_assertion: v })} />
        </div>
        <Field label="Encryption certificate" hint="PEM or base64; an RSA key." wide>
          {(fid, by) => <TextArea id={fid} aria-describedby={by} value={draft.encryption_certificate ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ encryption_certificate: e.target.value.trim() || null })} />}
        </Field>
        <Field label="Content encryption">
          {(fid) => (
            <SelectInput id={fid} value={draft.data_encryption ?? "aes256-gcm"} disabled={!editable} onChange={(e) => update({ data_encryption: e.target.value as SamlSpInput["data_encryption"] })}>
              <option value="aes256-gcm">AES-256-GCM</option>
              <option value="aes128-gcm">AES-128-GCM</option>
              <option value="aes256-cbc">AES-256-CBC (legacy SPs)</option>
              <option value="aes128-cbc">AES-128-CBC (legacy SPs)</option>
            </SelectInput>
          )}
        </Field>
        <Field label="Key transport">
          {(fid) => (
            <SelectInput id={fid} value={draft.key_transport ?? "rsa-oaep-mgf1p"} disabled={!editable} onChange={(e) => update({ key_transport: e.target.value as SamlSpInput["key_transport"] })}>
              <option value="rsa-oaep-mgf1p">RSA-OAEP (SHA-1, widest support)</option>
              <option value="rsa-oaep-sha256">RSA-OAEP (SHA-256)</option>
            </SelectInput>
          )}
        </Field>
      </Section>
      <Section id="saml-idp-init" title="IdP-initiated sign-in" description="Sign-in started at rIDM (an app launcher link) rather than at the SP. Unsolicited responses are the easier kind to replay, so this is off unless the SP needs it.">
        <div className="sm:col-span-2">
          <Toggle label="Allow IdP-initiated sign-in" checked={draft.allow_idp_initiated ?? false} disabled={!editable} onChange={(v) => update({ allow_idp_initiated: v })} />
        </div>
        <Field label="Default RelayState" hint="Where the SP sends the user afterwards, when the link names none.">
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={draft.default_relay_state ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ default_relay_state: e.target.value || null })} />}
        </Field>
        {draft.allow_idp_initiated && initUrl && (
          <Field label="Sign-in link">
            {() => (
              <span className="flex min-w-0 items-center gap-2">
                <code className="min-w-0 break-all font-mono text-[0.8125rem] text-ink">{initUrl}</code>
                <CopyButton value={initUrl} label="Copy sign-in link" />
              </span>
            )}
          </Field>
        )}
      </Section>
      {editable && <DeleteButton what="service provider" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description="Its users can no longer sign in to it through rIDM." />}
    </div>
  );
}
