"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState, type ChangeEvent, type FormEvent } from "react";
import { Field, NumberInput, SaveIndicator, Section, SelectInput, TagsInput, TextArea, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { href, type IdentityProvider, type IdentityProviderPatch, type IdpPreset, type KerberosSettings, type KeytabReport, type LdapSettings, type SamlUpstreamSettings } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "../access/common";
import { CopyButton } from "../clients/reveal";
import { JsonInput } from "../users/attributes";
import { fileToBase64, KerberosUpstreamSection } from "./kerberos-upstream";
import { LdapUpstreamSection } from "./ldap-upstream";
import { SamlSpDetails, SamlUpstreamSection } from "./saml-upstream";

const POLICY_HINT: Record<IdentityProvider["link_policy"], string> = {
  verified_email: "An existing account with the same address is linked when both sides verified it; otherwise the sign-in is refused and the user links from their account page.",
  explicit: "Never linked by email: the user signs in the usual way and links the provider from their account page.",
  always_new: "A new account every time; an address another account holds is left off it.",
};

export function IdentityProvidersPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { client, can } = useConsole();
  const [creating, setCreating] = useState(false);
  const list = useQuery({
    queryKey: ["idps", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/identity-providers", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  return (
    <>
      <PageHeader
        title="Identity providers"
        sub="Upstream OpenID Connect, OAuth 2.0 and SAML 2.0 providers users can sign in through, LDAP or Active Directory directories they sign in with, and Kerberos realms for desktop sign-in."
        actions={
          can("ridm:idps:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New provider
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Providers">
            {list.isPending ? (
              <Spinner label="Loading…" />
            ) : list.isError ? (
              <ErrorLine error={list.error} />
            ) : list.data.length === 0 ? (
              <p className="text-[0.875rem] text-muted">No providers yet.</p>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {list.data.map((p) => (
                  <li key={p.id}>
                    <Link
                      href={href("identity-providers", tenant, { idp: p.id })}
                      aria-current={p.id === selected ? "page" : undefined}
                      className={`flex items-center justify-between gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${p.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate">{p.display_name}</span>
                        <span className="block truncate text-[0.75rem] text-muted">
                          {p.alias} · {p.preset ?? p.kind}
                        </span>
                      </span>
                      {!p.enabled ? <Badge>off</Badge> : p.hidden ? <Badge>hidden</Badge> : null}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        }
        detail={selected ? <ProviderView key={selected} tenant={tenant} id={selected} /> : <p className="text-[0.9rem] text-muted">Choose a provider.</p>}
      />
      <CreateProvider tenant={tenant} open={creating} onOpenChange={setCreating} />
    </>
  );
}

function usePresets(tenant: string) {
  const { client } = useConsole();
  return useQuery({
    queryKey: ["idp-presets", tenant],
    staleTime: Infinity,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/identity-providers/presets", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data as IdpPreset[];
    },
  });
}

function CreateProvider({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const presets = usePresets(tenant);
  const [preset, setPreset] = useState("");
  const [alias, setAlias] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [metadataUrl, setMetadataUrl] = useState("");
  const [metadata, setMetadata] = useState("");
  const [vendor, setVendor] = useState<LdapSettings["vendor"]>("active_directory");
  const [ldapUrl, setLdapUrl] = useState("");
  const [usersDn, setUsersDn] = useState("");
  const [bindDn, setBindDn] = useState("");
  const [bindPassword, setBindPassword] = useState("");
  const [keytab, setKeytab] = useState<{ b64: string; report: KeytabReport } | null>(null);
  const [keytabError, setKeytabError] = useState<string | null>(null);
  const [spn, setSpn] = useState("");
  const [networks, setNetworks] = useState<string[]>([]);
  const saml = preset === "saml";
  const ldap = preset === "ldap";
  const kerberos = preset === "kerberos";
  const chosen = presets.data?.find((p) => p.name === preset) ?? null;
  const pickPreset = (name: string) => {
    setPreset(name);
    const p = presets.data?.find((x) => x.name === name);
    if (p) {
      if (!alias) setAlias(p.name);
      if (!displayName) setDisplayName(p.display_name);
    }
  };
  const problem = (error: { errors?: { field: string; message: string }[] | null; detail?: string | null; title: string }) =>
    new Error(error.errors?.map((e) => `${e.field} ${e.message}`).join("; ") || error.detail || error.title);
  const onKeytab = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setKeytab(null);
    setKeytabError(null);
    void fileToBase64(file).then(async (b64) => {
      // Read it first: what it holds, and which service it is for.
      const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers/kerberos-keytab", { params: { path: { slug: tenant } }, body: { keytab: b64 } });
      if (error) {
        setKeytabError(problem(error).message);
        return;
      }
      setKeytab({ b64, report: data });
      setSpn(data.service_principals[0] ?? "");
    });
  };
  const create = useMutation({
    mutationFn: async () => {
      if (kerberos) {
        const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers", {
          params: { path: { slug: tenant } },
          body: {
            alias: alias.trim(),
            kind: "kerberos",
            display_name: displayName.trim() || null,
            kerberos: { keytab: keytab?.b64 ?? null, service_principal: spn || null, trusted_networks: networks } as KerberosSettings,
          } as never,
        });
        if (error) throw problem(error);
        return data;
      }
      if (ldap) {
        // The vendor's defaults fill in the attributes and filters; review them on the provider page.
        const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers", {
          params: { path: { slug: tenant } },
          body: {
            alias: alias.trim(),
            kind: "ldap",
            display_name: displayName.trim() || null,
            ldap: { vendor, url: ldapUrl.trim(), users_dn: usersDn.trim(), bind_dn: bindDn.trim() || null, bind_password: bindPassword || null },
          } as never,
        });
        if (error) throw problem(error);
        return data;
      }
      if (saml) {
        // The IdP's metadata fills in everything; the URL is kept for the daily refresh.
        const read = await client.POST("/admin/tenants/{slug}/identity-providers/saml-metadata", {
          params: { path: { slug: tenant } },
          body: metadataUrl.trim() ? { url: metadataUrl.trim() } : { metadata },
        });
        if (read.error) throw problem(read.error);
        const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers", {
          params: { path: { slug: tenant } },
          body: { alias: alias.trim(), kind: "saml", display_name: displayName.trim() || null, saml: read.data as SamlUpstreamSettings } as never,
        });
        if (error) throw problem(error);
        return data;
      }
      const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers", {
        params: { path: { slug: tenant } },
        body: {
          alias: alias.trim(),
          preset: preset || null,
          display_name: displayName.trim() || null,
          issuer: issuer.trim() || null,
          client_id: clientId.trim(),
          client_secret: secret || null,
        } as never,
      });
      if (error) throw problem(error);
      return data;
    },
    onSuccess: (p) => {
      void qc.invalidateQueries({ queryKey: ["idps", tenant] });
      setAlias("");
      setDisplayName("");
      setIssuer("");
      setClientId("");
      setSecret("");
      setPreset("");
      setMetadataUrl("");
      setMetadata("");
      setLdapUrl("");
      setUsersDn("");
      setBindDn("");
      setBindPassword("");
      setKeytab(null);
      setSpn("");
      setNetworks([]);
      onOpenChange(false);
      router.push(href("identity-providers", tenant, { idp: p.id }));
    },
  });
  const needsIssuer = !saml && !ldap && !kerberos && (!chosen || chosen.kind === "oidc");
  const ready = alias.trim() && (kerberos ? keytab && spn : ldap ? ldapUrl.trim() && usersDn.trim() : saml ? metadataUrl.trim() || metadata.trim() : clientId.trim());
  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void file.text().then(setMetadata);
  };
  return (
    <CreateDialog
      open={open}
      onOpenChange={onOpenChange}
      title="New identity provider"
      description="Pick a preset for the common providers, give an OpenID Connect issuer (its endpoints are discovered), a SAML identity provider's metadata, an LDAP directory, or a Kerberos service's keytab. Register the URLs shown afterwards with the provider."
      submitLabel="Create provider"
      pending={create.isPending}
      error={create.error?.message ?? null}
      onSubmit={() => ready && create.mutate()}
    >
      <Field label="Preset" hint={chosen?.hint}>
        {(id, by) => (
          <SelectInput id={id} aria-describedby={by} value={preset} onChange={(e) => pickPreset(e.target.value)}>
            <option value="">Custom (OpenID Connect)</option>
            <option value="saml">SAML 2.0</option>
            <option value="ldap">LDAP / Active Directory</option>
            <option value="kerberos">Kerberos / SPNEGO (desktop sign-in)</option>
            {(presets.data ?? []).map((p) => (
              <option key={p.name} value={p.name}>
                {p.display_name}
              </option>
            ))}
          </SelectInput>
        )}
      </Field>
      <Field label="Alias" hint={ldap || kerberos ? "Lowercase letters, digits and hyphens." : "In the callback URL: lowercase letters, digits and hyphens."}>
        {(id, by) => <TextInput id={id} aria-describedby={by} value={alias} onChange={(e) => setAlias(e.target.value)} autoFocus required placeholder={kerberos ? "windows" : saml || ldap ? "corp" : "google"} spellCheck={false} />}
      </Field>
      <Field label="Display name" hint={ldap ? "Shown to administrators, and in messages to directory users." : "On the login button: “Continue with …”."}>
        {(id, by) => <TextInput id={id} aria-describedby={by} value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder={chosen?.display_name ?? "Company SSO"} />}
      </Field>
      {needsIssuer && (
        <Field label="Issuer" hint={chosen ? "The preset's issuer; change it for a self-managed instance or a single Microsoft directory." : "The OpenID Connect issuer URL; its discovery document names the endpoints."}>
          {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder={chosen?.issuer ?? "https://idp.example.com"} spellCheck={false} />}
        </Field>
      )}
      {kerberos ? (
        <>
          <div className="flex flex-col gap-1.5">
            <label className="inline-flex min-h-9 cursor-pointer items-center gap-2 self-start rounded-[var(--radius)] border border-line bg-paper px-3.5 text-[0.875rem] font-medium text-ink hover:bg-ground focus-within:outline-2 focus-within:outline-accent">
              <input type="file" accept=".keytab,application/octet-stream" className="sr-only" onChange={onKeytab} />
              {keytab ? "Choose another keytab" : "Choose the service's keytab"}
            </label>
            <p className="text-[0.8125rem] text-muted" aria-live="polite">
              {keytabError ??
                (keytab
                  ? `${keytab.report.entries.length} key${keytab.report.entries.length === 1 ? "" : "s"}; ${keytab.report.service_principals.length ? `AES keys for ${keytab.report.service_principals.join(", ")}` : "no AES key rIDM can use"}.`
                  : "Exported for HTTP/<host>@REALM with ktpass (Active Directory) or kadmin ktadd (MIT). Stored encrypted.")}
            </p>
          </div>
          {keytab && keytab.report.service_principals.length > 1 && (
            <Field label="Service principal">
              {(id) => (
                <SelectInput id={id} value={spn} onChange={(e) => setSpn(e.target.value)}>
                  {keytab.report.service_principals.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </SelectInput>
              )}
            </Field>
          )}
          <Field label="Trusted networks" hint="Where the login page tries desktop sign-in on its own; elsewhere users click the button. Optional.">
            {(id, by) => <TagsInput id={id} describedBy={by} value={networks} onChange={setNetworks} placeholder="10.0.0.0/8" />}
          </Field>
        </>
      ) : ldap ? (
        <>
          <Field label="Server">
            {(id) => (
              <SelectInput id={id} value={vendor} onChange={(e) => setVendor(e.target.value as LdapSettings["vendor"])}>
                <option value="active_directory">Active Directory</option>
                <option value="openldap">OpenLDAP</option>
                <option value="other">Other LDAP</option>
              </SelectInput>
            )}
          </Field>
          <Field label="URL" hint="ldaps://host:636; StartTLS and a private CA are set on the provider page.">
            {(id, by) => <TextInput id={id} aria-describedby={by} value={ldapUrl} onChange={(e) => setLdapUrl(e.target.value)} required placeholder="ldaps://dc1.corp.example" spellCheck={false} />}
          </Field>
          <Field label="Users DN" hint="The base users are searched under.">
            {(id, by) => <TextInput id={id} aria-describedby={by} value={usersDn} onChange={(e) => setUsersDn(e.target.value)} required placeholder="ou=people,dc=corp,dc=example" spellCheck={false} />}
          </Field>
          <Field label="Bind DN" hint="The service account rIDM searches as; empty searches anonymously.">
            {(id, by) => <TextInput id={id} aria-describedby={by} value={bindDn} onChange={(e) => setBindDn(e.target.value)} placeholder="cn=ridm,ou=services,dc=corp,dc=example" spellCheck={false} />}
          </Field>
          <Field label="Bind password" hint="Stored encrypted and never shown again.">
            {(id, by) => <TextInput id={id} aria-describedby={by} type="password" value={bindPassword} disabled={!bindDn.trim()} onChange={(e) => setBindPassword(e.target.value)} autoComplete="new-password" />}
          </Field>
        </>
      ) : saml ? (
        <>
          <Field label="Metadata URL" hint="Where the identity provider publishes its metadata; rIDM re-reads it daily.">
            {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={metadataUrl} onChange={(e) => setMetadataUrl(e.target.value)} placeholder="https://idp.example.com/saml/metadata" spellCheck={false} />}
          </Field>
          <Field label="Or its metadata" hint="The EntityDescriptor XML, when there is no URL to fetch it from.">
            {(id, by) => <TextArea id={id} aria-describedby={by} value={metadata} disabled={!!metadataUrl.trim()} spellCheck={false} placeholder="<md:EntityDescriptor …>" onChange={(e) => setMetadata(e.target.value)} />}
          </Field>
          <label className="inline-flex cursor-pointer items-center gap-2 self-start text-[0.875rem] text-accent hover:underline underline-offset-4">
            <input type="file" accept=".xml,application/xml,text/xml,application/samlmetadata+xml" className="sr-only" onChange={onFile} />
            Upload a metadata file
          </label>
        </>
      ) : (
        <>
          <Field label="Client ID">{(id) => <TextInput id={id} value={clientId} onChange={(e) => setClientId(e.target.value)} required spellCheck={false} autoComplete="off" />}</Field>
          <Field label="Client secret" hint="Stored encrypted and never shown again. Leave empty for a public client using PKCE.">
            {(id, by) => <TextInput id={id} aria-describedby={by} type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" />}
          </Field>
        </>
      )}
    </CreateDialog>
  );
}

function ProviderView({ tenant, id }: { tenant: string; id: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const editable = can("ridm:idps:write");
  const query = useQuery({
    queryKey: ["idp", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/identity-providers/{idp}", { params: { path: { slug: tenant, idp: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<IdentityProvider | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const save = useCallback(
    async (patch: IdentityProviderPatch, { keepalive }: SaveOptions) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/identity-providers/{idp}", { params: { path: { slug: tenant, idp: id } }, body: patch as never, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["idp", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.errors?.map((e) => `${e.field} ${e.message}`).join("; ") || error.detail || error.title);
      }
      qc.setQueryData(["idp", tenant, id], data);
      void qc.invalidateQueries({ queryKey: ["idps", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save, { baseline: query.data });
  const update = (patch: IdentityProviderPatch) => {
    setDraft((d) => (d ? ({ ...d, ...patch } as IdentityProvider) : d));
    if (editable) queue(patch);
  };
  // The SAML settings are saved as a whole; the refresh status stays as it was read.
  const updateSaml = (settings: SamlUpstreamSettings) => {
    setDraft((d) => (d && d.saml ? { ...d, saml: { ...d.saml, ...settings } } : d));
    if (editable) queue({ saml: settings });
  };
  // So are a directory's; its bind password and sync status have their own controls.
  const updateLdap = (settings: Omit<LdapSettings, "bind_password">) => {
    setDraft((d) => (d && d.ldap ? { ...d, ldap: { ...d.ldap, ...settings } as IdentityProvider["ldap"] } : d));
    if (editable) queue({ ldap: settings as LdapSettings });
  };
  // And a Kerberos realm's; its keytab is uploaded on its own.
  const updateKerberos = (settings: Omit<KerberosSettings, "keytab">) => {
    setDraft((d) => (d && d.kerberos ? { ...d, kerberos: { ...d.kerberos, ...settings } as IdentityProvider["kerberos"] } : d));
    if (editable) queue({ kerberos: settings as KerberosSettings });
  };
  const all = useQuery({
    queryKey: ["idps", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/identity-providers", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [secret, setSecret] = useState("");
  const setSecretMutation = useMutation({
    mutationFn: async (value: string | null) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/identity-providers/{idp}", { params: { path: { slug: tenant, idp: id } }, body: { client_secret: value } as never });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (p) => {
      qc.setQueryData(["idp", tenant, id], p);
      setDraft(p);
      setSecret("");
    },
  });
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/identity-providers/{idp}", { params: { path: { slug: tenant, idp: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["idps", tenant] });
      router.push(href("identity-providers", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading…" />;
  const m = draft.mappers;
  const isSaml = draft.kind === "saml";
  const isLdap = draft.kind === "ldap";
  const isKerberos = draft.kind === "kerberos";
  const setMapper = (patch: Partial<IdentityProvider["mappers"]>) => update({ mappers: { ...m, ...patch } });
  const submitSecret = (e: FormEvent) => {
    e.preventDefault();
    if (secret) setSecretMutation.mutate(secret);
  };
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">{draft.display_name}</h2>
        <SaveIndicator status={status} error={error} />
      </div>
      {isLdap || isKerberos ? null : isSaml ? (
        <SamlSpDetails provider={draft} />
      ) : (
        <Card title="Callback URL">
          <p className="text-[0.875rem] text-muted">Register this redirect URI with the provider.</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <code className="break-all rounded-[var(--radius)] bg-ground px-2 py-1 font-mono text-[0.8125rem] text-ink">{draft.callback_url}</code>
            <CopyButton value={draft.callback_url} label="Copy callback URL" />
          </div>
        </Card>
      )}
      <Section id="idp-general" title="Provider">
        <Field label="Display name">{(fid) => <TextInput id={fid} value={draft.display_name} disabled={!editable} onChange={(e) => update({ display_name: e.target.value })} />}</Field>
        <Field label="Alias" hint={isLdap || isKerberos ? "Lowercase letters, digits and hyphens." : isSaml ? "Changing it changes rIDM's entity ID and URLs: the identity provider must be told." : "Changing it changes the callback URL."}>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={draft.alias} disabled={!editable} spellCheck={false} onChange={(e) => update({ alias: e.target.value })} />}
        </Field>
        <Field label="Protocol">
          {(fid) => (
            <SelectInput id={fid} value={draft.kind} disabled={!editable || isSaml || isLdap || isKerberos} onChange={(e) => update({ kind: e.target.value as IdentityProvider["kind"] })}>
              {isKerberos ? (
                <option value="kerberos">Kerberos / SPNEGO</option>
              ) : isLdap ? (
                <option value="ldap">LDAP / Active Directory</option>
              ) : isSaml ? (
                <option value="saml">SAML 2.0</option>
              ) : (
                <>
                  <option value="oidc">OpenID Connect</option>
                  <option value="oauth2">OAuth 2.0</option>
                </>
              )}
            </SelectInput>
          )}
        </Field>
        <Field label="Order" hint={isLdap ? "Which directory is asked first about a username no account has." : isKerberos ? "Which Kerberos button the login page shows when there are several." : "Position on the login page."}>
          {(fid, by) => <NumberInput id={fid} describedBy={by} value={draft.sort_order} min={-1000} max={1000} onValue={(v) => v !== null && update({ sort_order: v })} />}
        </Field>
        <div className="sm:col-span-2 flex flex-col gap-1">
          <Toggle label="Enabled" hint={isLdap ? "A disabled directory signs nobody in and is not synced." : "Disabled providers sign nobody in."} checked={draft.enabled} disabled={!editable} onChange={(v) => update({ enabled: v })} />
          {!isLdap && (
            <Toggle
              label="Hidden"
              hint={isKerberos ? "No button on the login page; automatic sign-in from the trusted networks goes on." : "Not offered on the login page; reachable through a direct link only."}
              checked={draft.hidden}
              disabled={!editable}
              onChange={(v) => update({ hidden: v })}
            />
          )}
        </div>
      </Section>
      {isKerberos ? (
        <KerberosUpstreamSection
          tenant={tenant}
          provider={draft}
          providers={all.data ?? []}
          editable={editable}
          onChange={updateKerberos}
          onSaved={(p) => {
            qc.setQueryData(["idp", tenant, id], p);
            setDraft(p);
          }}
        />
      ) : isLdap ? (
        <LdapUpstreamSection
          tenant={tenant}
          provider={draft}
          editable={editable}
          onChange={updateLdap}
          onSaved={(p) => {
            qc.setQueryData(["idp", tenant, id], p);
            setDraft(p);
          }}
        />
      ) : isSaml ? (
        <SamlUpstreamSection
          tenant={tenant}
          provider={draft}
          editable={editable}
          onChange={updateSaml}
          onRefreshed={(p) => {
            qc.setQueryData(["idp", tenant, id], p);
            setDraft(p);
          }}
        />
      ) : (
        <>
          <Section id="idp-endpoints" title="Endpoints" description="For OpenID Connect a new issuer re-discovers the endpoints; fill them in by hand for providers without discovery.">
            <Field label="Issuer" wide>
              {(fid) => <TextInput id={fid} type="url" value={draft.issuer ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ issuer: e.target.value || null })} />}
            </Field>
            <Field label="Authorization endpoint" wide>
              {(fid) => <TextInput id={fid} type="url" value={draft.authorization_endpoint ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ authorization_endpoint: e.target.value || null })} />}
            </Field>
            <Field label="Token endpoint" wide>
              {(fid) => <TextInput id={fid} type="url" value={draft.token_endpoint ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ token_endpoint: e.target.value || null })} />}
            </Field>
            <Field label="Userinfo endpoint" wide>
              {(fid) => <TextInput id={fid} type="url" value={draft.userinfo_endpoint ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ userinfo_endpoint: e.target.value || null })} />}
            </Field>
            <Field label="JWKS URI" wide>
              {(fid) => <TextInput id={fid} type="url" value={draft.jwks_uri ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ jwks_uri: e.target.value || null })} />}
            </Field>
          </Section>
          <Section id="idp-client" title="Client">
            <Field label="Client ID">{(fid) => <TextInput id={fid} value={draft.client_id} disabled={!editable} spellCheck={false} autoComplete="off" onChange={(e) => update({ client_id: e.target.value })} />}</Field>
            <Field label="Token endpoint authentication">
              {(fid) => (
                <SelectInput id={fid} value={draft.token_endpoint_auth_method} disabled={!editable} onChange={(e) => update({ token_endpoint_auth_method: e.target.value as IdentityProvider["token_endpoint_auth_method"] })}>
                  <option value="client_secret_basic">client_secret_basic</option>
                  <option value="client_secret_post">client_secret_post</option>
                  <option value="none">none (PKCE only)</option>
                </SelectInput>
              )}
            </Field>
            <Field label="Scopes" wide>
              {(fid, by) => <TagsInput id={fid} describedBy={by} value={draft.scopes} onChange={(v) => update({ scopes: v })} placeholder="openid, email, profile" />}
            </Field>
            <div className="sm:col-span-2">
              <Toggle label="PKCE" hint="Required when no client secret is set." checked={draft.pkce} disabled={!editable} onChange={(v) => update({ pkce: v })} />
            </div>
            <form onSubmit={submitSecret} className="sm:col-span-2 flex flex-col gap-2">
              <Field label="Client secret" hint={draft.client_secret_set ? "A secret is stored. Enter a new one to replace it." : "No secret is stored: the client authenticates with PKCE alone."}>
                {(fid, by) => <TextInput id={fid} aria-describedby={by} type="password" value={secret} disabled={!editable} autoComplete="new-password" onChange={(e) => setSecret(e.target.value)} />}
              </Field>
              {editable && (
                <div className="flex flex-wrap gap-2">
                  <Button type="submit" variant="primary" disabled={!secret || setSecretMutation.isPending}>
                    {draft.client_secret_set ? "Replace secret" : "Set secret"}
                  </Button>
                  {draft.client_secret_set && (
                    <Button type="button" disabled={setSecretMutation.isPending} onClick={() => setSecretMutation.mutate(null)}>
                      Clear secret
                    </Button>
                  )}
                </div>
              )}
              <ErrorLine error={setSecretMutation.error} />
            </form>
          </Section>
        </>
      )}
      {!isKerberos && (
        <Section id="idp-accounts" title="Accounts" description="How an upstream identity becomes a local account, and what it fills in.">
          <Field label="Link policy" hint={POLICY_HINT[draft.link_policy]} wide>
            {(fid, by) => (
              <SelectInput id={fid} aria-describedby={by} value={draft.link_policy} disabled={!editable} onChange={(e) => update({ link_policy: e.target.value as IdentityProvider["link_policy"] })}>
                <option value="verified_email">Link by verified email</option>
                <option value="explicit">Explicit linking only</option>
                <option value="always_new">Always a new account</option>
              </SelectInput>
            )}
          </Field>
          <div className="sm:col-span-2">
            <Toggle
              label="Trust the provider's email addresses"
              hint={isLdap ? "Treat the directory's addresses as verified (a directory says nothing about it). Needed to link existing accounts by email." : "Treat them as verified even without an email_verified claim."}
              checked={draft.trust_email}
              disabled={!editable}
              onChange={(v) => update({ trust_email: v })}
            />
          </div>
          {!isLdap && (
            <Field label={isSaml ? "Subject attribute" : "Subject claim"} hint={isSaml ? "The stable identifier; the NameID when empty. Name an attribute for identity providers that send transient NameIDs." : "The stable identifier; sub when empty."}>
              {(fid, by) => <TextInput id={fid} aria-describedby={by} value={m.subject ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => setMapper({ subject: e.target.value || null })} />}
            </Field>
          )}
          <Field
            label={isSaml || isLdap ? "Username attribute" : "Username claim"}
            hint={
              isLdap
                ? "The directory attribute a username comes from; the one in Users above when empty."
                : isSaml
                  ? "preferred_username when empty; uid, eduPersonPrincipalName and the UPN count. The email, then alias-subject, stand in."
                  : "preferred_username when empty; the email, then alias-subject, stand in."
            }
          >
            {(fid, by) => <TextInput id={fid} aria-describedby={by} value={m.username ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => setMapper({ username: e.target.value || null })} />}
          </Field>
          <Field label={isSaml || isLdap ? "Email attribute" : "Email claim"} hint={isLdap ? "mail when empty." : isSaml ? "email when empty; mail and the standard attribute URIs count as email." : "email when empty."}>
            {(fid, by) => <TextInput id={fid} aria-describedby={by} value={m.email ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => setMapper({ email: e.target.value || null })} />}
          </Field>
          {!isLdap && (
            <Field label="Email verified claim" hint="email_verified when empty.">
              {(fid, by) => <TextInput id={fid} aria-describedby={by} value={m.email_verified ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => setMapper({ email_verified: e.target.value || null })} />}
            </Field>
          )}
          <Field
            label="Profile attributes"
            hint={
              isLdap
                ? 'JSON object of attribute name → directory attribute, refreshed at every sign-in and sync (and written back when the directory is writable): {"first_name": "givenName"}.'
                : 'JSON object of attribute name → claim name, written on every sign-in: {"first_name": "given_name"}. A dot descends into an object.'
            }
            wide
          >
            {(fid, by) => <JsonInput id={fid} describedBy={by} value={Object.keys(m.attributes ?? {}).length ? m.attributes : null} disabled={!editable} onChange={(v) => setMapper({ attributes: (v as Record<string, string> | null) ?? {} })} />}
          </Field>
        </Section>
      )}
      {editable && <DeleteButton what="identity provider" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description={isLdap ? "Its users keep their accounts but have no password until one is set; the groups it synced stay as they are." : "Identities linked through it are removed; the users keep their accounts."} />}
    </div>
  );
}
