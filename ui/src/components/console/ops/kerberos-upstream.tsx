"use client";

import { useMutation } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { type ChangeEvent } from "react";
import { Field, NumberInput, Section, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card } from "@/components/console/ui";
import type { IdentityProvider, KerberosSettings, KerberosUpstream } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

/** The settings of a stored Kerberos provider, without what only the server knows. */
export function kerberosSettingsOf(k: KerberosUpstream): Omit<KerberosSettings, "keytab"> {
  const settings: Partial<KerberosUpstream> = { ...k };
  delete settings.keytab_set;
  delete settings.keytab_entries;
  delete settings.supported;
  return settings as Omit<KerberosSettings, "keytab">;
}

/** A file's bytes as base64, the way the admin API takes a keytab. */
export async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

/** The directory attribute the server looks a name up by (`default_ldap_attribute` in the API). */
function defaultAttribute(vendor: string | undefined, form: KerberosSettings["name_form"]): string {
  if (vendor === "active_directory") return form === "principal" ? "userPrincipalName" : "sAMAccountName";
  return form === "principal" ? "krbPrincipalName" : "uid";
}

function problem(error: { errors?: { field: string; message: string }[] | null; detail?: string | null; title: string }): Error {
  return new Error(error.errors?.map((e) => `${e.field} ${e.message}`).join("; ") || error.detail || error.title);
}

/** A Kerberos provider's settings, auto-saved as a whole on every change; the keytab has its own control. */
export function KerberosUpstreamSection({
  tenant,
  provider,
  providers,
  editable,
  onChange,
  onSaved,
}: {
  tenant: string;
  provider: IdentityProvider;
  /** The tenant's providers, for the directory picker. */
  providers: IdentityProvider[];
  editable: boolean;
  onChange: (s: Omit<KerberosSettings, "keytab">) => void;
  onSaved: (p: IdentityProvider) => void;
}) {
  const { client } = useConsole();
  const krb = provider.kerberos;
  const s = krb ? kerberosSettingsOf(krb) : null;
  const setKeytab = useMutation({
    mutationFn: async (keytab: string) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/identity-providers/{idp}", {
        params: { path: { slug: tenant, idp: provider.id } },
        body: { kerberos: { ...s, keytab } } as never,
      });
      if (error) throw problem(error);
      return data;
    },
    onSuccess: onSaved,
  });
  if (!krb || !s) return null;
  const set = (patch: Partial<Omit<KerberosSettings, "keytab">>) => onChange({ ...s, ...patch });
  const directories = providers.filter((p) => p.kind === "ldap");
  const directory = directories.find((d) => d.id === s.ldap_idp_id) ?? null;
  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (file) void fileToBase64(file).then((b64) => setKeytab.mutate(b64));
  };
  return (
    <>
      {!krb.supported && (
        <Card title="Not available in this build">
          <p className="text-[0.875rem] text-muted">
            This rIDM was built without the <code className="font-mono">kerberos</code> feature: the provider can be configured, but nobody can sign in with it. The released image and binaries include it.
          </p>
        </Card>
      )}
      <Card
        title="Keytab"
        actions={
          editable ? (
            <label className="inline-flex min-h-9 cursor-pointer items-center gap-2 rounded-[var(--radius)] border border-line bg-paper px-3.5 text-[0.875rem] font-medium text-ink hover:bg-ground focus-within:outline-2 focus-within:outline-accent">
              <input type="file" accept=".keytab,application/octet-stream" className="sr-only" onChange={onFile} disabled={setKeytab.isPending} />
              <Upload className="size-4" aria-hidden />
              {krb.keytab_set ? "Replace keytab" : "Upload keytab"}
            </label>
          ) : undefined
        }
      >
        {krb.keytab_set ? (
          <ul className="flex flex-col gap-1.5">
            {krb.keytab_entries.map((e, i) => (
              <li key={`${e.principal}-${e.kvno}-${e.etype}-${i}`} className="flex flex-wrap items-center gap-2 text-[0.8125rem]">
                <code className="break-all font-mono text-ink">{e.principal}</code>
                <span className="text-muted">
                  kvno {e.kvno} · {e.etype_name}
                </span>
                {!e.supported && <Badge tone="danger">not usable</Badge>}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[0.875rem] text-danger">No keytab is stored: nobody can sign in until one is uploaded.</p>
        )}
        <p className="mt-2 text-[0.8125rem] text-muted">Stored encrypted; keys are never shown. rIDM accepts AES tickets (aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96) only.</p>
        {editable && krb.keytab_set && (
          <Button className="mt-2" disabled={setKeytab.isPending} onClick={() => setKeytab.mutate("")}>
            Remove keytab
          </Button>
        )}
        <ErrorLine error={setKeytab.error} />
      </Card>
      <Section id="idp-kerberos-service" title="Service" description="Browsers ask the KDC for a ticket to HTTP/<the host they reach rIDM by>. Register that name for rIDM's service account (setspn on Active Directory) and export its keytab.">
        <Field label="Service principal" hint="HTTP/host@REALM, one the keytab has a key for." wide>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.service_principal ?? ""} disabled={!editable} spellCheck={false} placeholder="HTTP/sso.corp.example@CORP.EXAMPLE" onChange={(e) => set({ service_principal: e.target.value || null })} />}
        </Field>
        <Field label="Realms" hint="Whose users may sign in; the service's realm when empty. Add a trusted realm only if its names cannot collide with this one's." wide>
          {(fid, by) => <TagsInput id={fid} describedBy={by} value={s.realms} onChange={(v) => set({ realms: v })} placeholder="CORP.EXAMPLE" />}
        </Field>
        <Field label="Clock skew" hint="How far a client's clock may be from rIDM's.">
          {(fid, by) => <NumberInput id={fid} describedBy={by} value={s.max_skew_seconds} min={30} max={900} unit="s" disabled={!editable} onValue={(v) => v !== null && set({ max_skew_seconds: v })} />}
        </Field>
      </Section>
      <Section id="idp-kerberos-accounts" title="Accounts" description="A ticket names a principal and nothing else: this is how it finds its rIDM account.">
        <Field label="Name" hint={s.name_form === "principal" ? "The whole principal: alice@CORP.EXAMPLE." : "The principal without its realm: alice."}>
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={s.name_form} disabled={!editable} onChange={(e) => set({ name_form: e.target.value as KerberosSettings["name_form"] })}>
              <option value="local_part">Without the realm</option>
              <option value="principal">The whole principal</option>
            </SelectInput>
          )}
        </Field>
        <Field label="Directory" hint={directory ? "The name is looked up there and the user imported or refreshed, as a password sign-in would." : "No directory: local accounts are matched by username."}>
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={s.ldap_idp_id ?? ""} disabled={!editable} onChange={(e) => set({ ldap_idp_id: e.target.value || null, ldap_attribute: e.target.value ? s.ldap_attribute : null })}>
              <option value="">None</option>
              {directories.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.display_name}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
        {directory ? (
          <Field label="Directory attribute" hint="The attribute holding the name.">
            {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.ldap_attribute ?? ""} disabled={!editable} spellCheck={false} placeholder={defaultAttribute(directory.ldap?.vendor, s.name_form)} onChange={(e) => set({ ldap_attribute: e.target.value || null })} />}
          </Field>
        ) : (
          <div className="sm:col-span-2 flex flex-col gap-1">
            <Toggle label="Match usernames" hint="Sign in the account whose username is the name, and link it." checked={s.match_username} disabled={!editable} onChange={(v) => set({ match_username: v })} />
            <Toggle label="Create accounts" hint="An account for a principal no account matches, named by it." checked={s.create_users} disabled={!editable} onChange={(v) => set({ create_users: v })} />
          </div>
        )}
      </Section>
      <Section
        id="idp-kerberos-networks"
        title="Automatic sign-in"
        description="From these networks the login page asks the browser for a ticket on its own; elsewhere users click the button. Browsers answer only for sites their policy trusts (Chrome's AuthServerAllowlist, Firefox's network.negotiate-auth.trusted-uris, the Windows Local intranet zone)."
      >
        <Field label="Trusted networks" hint="CIDRs or addresses, as rIDM sees clients (behind a proxy, set TRUSTED_PROXIES). They decide when to ask, not who may sign in." wide>
          {(fid, by) => <TagsInput id={fid} describedBy={by} value={s.trusted_networks} onChange={(v) => set({ trusted_networks: v })} placeholder="10.0.0.0/8, 192.168.0.0/16" />}
        </Field>
      </Section>
    </>
  );
}
