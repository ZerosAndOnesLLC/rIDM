"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { PlugZap, RefreshCw } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Field, NumberInput, Section, SelectInput, TagsInput, TextArea, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, Row } from "@/components/console/ui";
import type { IdentityProvider, LdapSettings, LdapSyncStats, LdapTestReport, LdapUpstream } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

/** The settings of a stored directory, without its sync status or password flag. */
export function ldapSettingsOf(l: LdapUpstream): Omit<LdapSettings, "bind_password"> {
  const settings: Partial<LdapUpstream> = { ...l };
  delete settings.bind_password_set;
  delete settings.last_sync_at;
  delete settings.last_full_sync_at;
  delete settings.last_sync_error;
  delete settings.last_sync_stats;
  return settings as Omit<LdapSettings, "bind_password">;
}

const VENDOR_HINT: Record<LdapSettings["vendor"], string> = {
  active_directory: "sAMAccountName, objectGUID and whenChanged; passwords are written as unicodePwd, which Active Directory accepts over TLS only.",
  openldap: "uid, entryUUID and modifyTimestamp; passwords are written with the Password Modify operation.",
  other: "The OpenLDAP defaults; change the attributes below to match the directory.",
};

/** The defaults the server fills in per vendor (`LdapVendor` in the API), applied when the vendor changes. */
const VENDOR_DEFAULTS: Record<LdapSettings["vendor"], Pick<LdapSettings, "user_object_filter" | "username_attribute" | "uuid_attribute" | "group_object_filter">> = {
  active_directory: { user_object_filter: "(&(objectCategory=person)(objectClass=user))", username_attribute: "sAMAccountName", uuid_attribute: "objectGUID", group_object_filter: "(objectClass=group)" },
  openldap: { user_object_filter: "(objectClass=inetOrgPerson)", username_attribute: "uid", uuid_attribute: "entryUUID", group_object_filter: "(objectClass=groupOfNames)" },
  other: { user_object_filter: "(objectClass=inetOrgPerson)", username_attribute: "uid", uuid_attribute: "entryUUID", group_object_filter: "(objectClass=groupOfNames)" },
};

function problem(error: { errors?: { field: string; message: string }[] | null; detail?: string | null; title: string }): Error {
  return new Error(error.errors?.map((e) => `${e.field} ${e.message}`).join("; ") || error.detail || error.title);
}

function StatsLine({ stats }: { stats: LdapSyncStats }) {
  const parts = [
    `${stats.read} read`,
    `${stats.created} created`,
    `${stats.updated} updated`,
    `${stats.disabled} disabled`,
    `${stats.enabled} enabled`,
    stats.skipped ? `${stats.skipped} skipped` : null,
    `${stats.groups_created + stats.groups_updated + stats.groups_deleted} group changes`,
    `${stats.memberships_added + stats.memberships_removed} membership changes`,
  ].filter(Boolean);
  return (
    <span>
      {stats.full ? "Full" : "Incremental"}: {parts.join(", ")}.
    </span>
  );
}

function TestResult({ report }: { report: LdapTestReport }) {
  return (
    <div className="flex flex-col gap-2" aria-live="polite">
      <div className="flex flex-wrap gap-2">
        <Badge tone={report.connected ? "ok" : "danger"}>{report.connected ? "connected" : "no connection"}</Badge>
        {report.connected && <Badge tone={report.bound ? "ok" : "danger"}>{report.bound ? "service account bound" : "bind refused"}</Badge>}
      </div>
      {report.error && <p className="text-[0.8125rem] text-danger">{report.error}</p>}
      {report.connected && report.bound && (
        <dl>
          <Row label="Users found">{report.users.length === 0 ? "none under the base" : report.users.map((u) => u.username ?? u.dn).join(", ")}</Row>
          <Row label="Groups found">{report.groups.length === 0 ? "none (or group sync is off)" : report.groups.join(", ")}</Row>
        </dl>
      )}
    </div>
  );
}

/** A directory's settings, auto-saved as a whole on every change; the bind password has its own form. */
export function LdapUpstreamSection({
  tenant,
  provider,
  editable,
  onChange,
  onSaved,
}: {
  tenant: string;
  provider: IdentityProvider;
  editable: boolean;
  onChange: (s: Omit<LdapSettings, "bind_password">) => void;
  onSaved: (p: IdentityProvider) => void;
}) {
  const { client } = useConsole();
  const [password, setPassword] = useState("");
  const [lastSync, setLastSync] = useState<LdapSyncStats | null>(null);
  const groups = useQuery({
    queryKey: ["groups", tenant],
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/groups", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const ldap = provider.ldap;
  const s = ldap ? ldapSettingsOf(ldap) : null;
  const setPasswordMutation = useMutation({
    mutationFn: async (value: string) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/identity-providers/{idp}", {
        params: { path: { slug: tenant, idp: provider.id } },
        body: { ldap: { ...s, bind_password: value } } as never,
      });
      if (error) throw problem(error);
      return data;
    },
    onSuccess: (p) => {
      setPassword("");
      onSaved(p);
    },
  });
  const test = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers/{idp}/ldap/test", { params: { path: { slug: tenant, idp: provider.id } } });
      if (error) throw problem(error);
      return data;
    },
  });
  const sync = useMutation({
    mutationFn: async (full: boolean) => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers/{idp}/ldap/sync", {
        params: { path: { slug: tenant, idp: provider.id } },
        body: { full },
      });
      if (error) throw problem(error);
      return data;
    },
    onSuccess: async (stats) => {
      setLastSync(stats);
      const { data } = await client.GET("/admin/tenants/{slug}/identity-providers/{idp}", { params: { path: { slug: tenant, idp: provider.id } } });
      if (data) onSaved(data);
    },
  });
  if (!ldap || !s) return null;
  const set = (patch: Partial<Omit<LdapSettings, "bind_password">>) => onChange({ ...s, ...patch });
  const plain = s.url.trim().toLowerCase().startsWith("ldap://");
  const submitPassword = (e: FormEvent) => {
    e.preventDefault();
    if (password) setPasswordMutation.mutate(password);
  };
  const status = ldap.last_sync_error
    ? `Last sync failed: ${ldap.last_sync_error}`
    : ldap.last_sync_at
      ? `Last synced ${new Date(ldap.last_sync_at).toLocaleString()}${ldap.last_full_sync_at ? `; last full sync ${new Date(ldap.last_full_sync_at).toLocaleString()}` : ""}.`
      : "Not synced yet: users are imported when they first sign in, or by a sync.";
  return (
    <>
      <Card
        title="Connection test"
        actions={
          editable ? (
            <Button disabled={test.isPending} onClick={() => test.mutate()}>
              <PlugZap className="size-4" aria-hidden />
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          ) : undefined
        }
      >
        {test.data ? <TestResult report={test.data} /> : <p className="text-[0.875rem] text-muted">Connects, binds as the service account and reads a few users and groups. Nothing is stored.</p>}
        <ErrorLine error={test.error} />
      </Card>
      <Section id="idp-ldap-connection" title="Directory" description="rIDM connects to the directory from the server. A directory on a private network needs the operator to open it with OUTBOUND_ALLOW_NETWORKS.">
        <Field label="Server" hint={VENDOR_HINT[s.vendor]}>
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={s.vendor} disabled={!editable} onChange={(e) => {
                const vendor = e.target.value as LdapSettings["vendor"];
                const d = VENDOR_DEFAULTS[vendor];
                set({ vendor, ...d, login_attributes: [d.username_attribute ?? "uid", "mail"] });
              }}
            >
              <option value="active_directory">Active Directory</option>
              <option value="openldap">OpenLDAP</option>
              <option value="other">Other LDAP</option>
            </SelectInput>
          )}
        </Field>
        <Field label="URL" hint="ldaps://host:636, or ldap://host:389 with StartTLS. Plain LDAP is accepted for loopback hosts only.">
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.url} disabled={!editable} spellCheck={false} placeholder="ldaps://dc1.corp.example" onChange={(e) => set({ url: e.target.value })} />}
        </Field>
        <div className="sm:col-span-2">
          <Toggle label="StartTLS" hint="Upgrade an ldap:// connection to TLS before anything is sent." checked={s.starttls} disabled={!editable || !plain} onChange={(v) => set({ starttls: v })} />
        </div>
        <Field label="CA certificate" hint="PEM certificate(s) of the CA that issued the directory's certificate (an internal CA). Empty trusts the server's platform roots." wide>
          {(fid, by) => <TextArea id={fid} aria-describedby={by} value={s.ca_certificate ?? ""} disabled={!editable} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => set({ ca_certificate: e.target.value || null })} />}
        </Field>
        <Field label="Timeout" hint="For connecting and for each operation.">
          {(fid, by) => <NumberInput id={fid} describedBy={by} value={s.timeout_secs} min={1} max={60} unit="s" disabled={!editable} onValue={(v) => v !== null && set({ timeout_secs: v })} />}
        </Field>
      </Section>
      <Section id="idp-ldap-account" title="Service account" description="The account rIDM searches the directory as (and, when writable, writes as). Without one, searches are anonymous.">
        <Field label="Bind DN" wide>
          {(fid) => <TextInput id={fid} value={s.bind_dn ?? ""} disabled={!editable} spellCheck={false} placeholder="cn=ridm,ou=services,dc=corp,dc=example" onChange={(e) => set({ bind_dn: e.target.value || null })} />}
        </Field>
        <form onSubmit={submitPassword} className="sm:col-span-2 flex flex-col gap-2">
          <Field label="Bind password" hint={ldap.bind_password_set ? "A password is stored (encrypted, never shown). Enter a new one to replace it." : "No password is stored."}>
            {(fid, by) => <TextInput id={fid} aria-describedby={by} type="password" value={password} disabled={!editable} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />}
          </Field>
          {editable && (
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="primary" disabled={!password || setPasswordMutation.isPending}>
                {ldap.bind_password_set ? "Replace password" : "Set password"}
              </Button>
              {ldap.bind_password_set && (
                <Button type="button" disabled={setPasswordMutation.isPending} onClick={() => setPasswordMutation.mutate("")}>
                  Clear password
                </Button>
              )}
            </div>
          )}
          <ErrorLine error={setPasswordMutation.error} />
        </form>
      </Section>
      <Section id="idp-ldap-users" title="Users" description="Where users are found, and what signing in matches against.">
        <Field label="Users DN" hint="The base users are searched under." wide>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.users_dn} disabled={!editable} spellCheck={false} placeholder="ou=people,dc=corp,dc=example" onChange={(e) => set({ users_dn: e.target.value })} />}
        </Field>
        <Field label="Scope">
          {(fid) => (
            <SelectInput id={fid} value={s.search_scope} disabled={!editable} onChange={(e) => set({ search_scope: e.target.value as LdapSettings["search_scope"] })}>
              <option value="subtree">The base and everything below</option>
              <option value="one">Direct children only</option>
            </SelectInput>
          )}
        </Field>
        <Field label="User filter" hint="Which entries are users.">
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.user_object_filter ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ user_object_filter: e.target.value || null })} />}
        </Field>
        <Field label="Username attribute" hint="A new account's username.">
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.username_attribute ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ username_attribute: e.target.value || null })} />}
        </Field>
        <Field label="UUID attribute" hint="Never changes for an entry: the link between the entry and the account.">
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.uuid_attribute ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ uuid_attribute: e.target.value || null })} />}
        </Field>
        <Field label="Sign-in attributes" hint="What a typed username or email is matched against (up to five)." wide>
          {(fid, by) => <TagsInput id={fid} describedBy={by} value={s.login_attributes} onChange={(v) => set({ login_attributes: v })} placeholder="uid, mail" />}
        </Field>
      </Section>
      <Section id="idp-ldap-groups" title="Groups" description="Directory groups become rIDM groups the directory owns: created, renamed, filled and deleted by the sync. Members added in rIDM who are not directory users are left alone.">
        <Field label="Groups DN" hint="Empty turns group sync off." wide>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.groups_dn ?? ""} disabled={!editable} spellCheck={false} placeholder="ou=groups,dc=corp,dc=example" onChange={(e) => set({ groups_dn: e.target.value || null })} />}
        </Field>
        <Field label="Group filter">
          {(fid) => <TextInput id={fid} value={s.group_object_filter ?? ""} disabled={!editable || !s.groups_dn} spellCheck={false} onChange={(e) => set({ group_object_filter: e.target.value || null })} />}
        </Field>
        <Field label="Name attribute">
          {(fid) => <TextInput id={fid} value={s.group_name_attribute ?? ""} disabled={!editable || !s.groups_dn} spellCheck={false} onChange={(e) => set({ group_name_attribute: e.target.value || null })} />}
        </Field>
        <Field label="Members are">
          {(fid) => (
            <SelectInput id={fid} value={s.group_membership} disabled={!editable || !s.groups_dn} onChange={(e) => {
                const membership = e.target.value as LdapSettings["group_membership"];
                set({ group_membership: membership, group_member_attribute: membership === "dn" ? "member" : "memberUid" });
              }}
            >
              <option value="dn">Entry DNs (groupOfNames, Active Directory)</option>
              <option value="username">Usernames (posixGroup memberUid)</option>
            </SelectInput>
          )}
        </Field>
        <Field label="Member attribute">
          {(fid) => <TextInput id={fid} value={s.group_member_attribute ?? ""} disabled={!editable || !s.groups_dn} spellCheck={false} onChange={(e) => set({ group_member_attribute: e.target.value || null })} />}
        </Field>
        <Field label="Create under" hint="The rIDM group synced groups go under." wide>
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={s.group_parent_id ?? ""} disabled={!editable || !s.groups_dn} onChange={(e) => set({ group_parent_id: e.target.value || null })}>
              <option value="">Top level</option>
              {(groups.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
      </Section>
      <Section id="idp-ldap-sync" title="Sync and write-back" description="Users are imported and refreshed when they sign in, and by the sync. A full sync also disables the users who left the directory (or were disabled in Active Directory), and enables them again when they come back.">
        <Field
          label="Edit mode"
          hint={
            s.edit_mode === "writable"
              ? "Password changes and resets, email and mapped attributes are written to the directory as the service account first."
              : "The directory is the only source: rIDM refuses to change its users' passwords, emails and mapped attributes."
          }
          wide
        >
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={s.edit_mode} disabled={!editable} onChange={(e) => set({ edit_mode: e.target.value as LdapSettings["edit_mode"] })}>
              <option value="read_only">Read-only</option>
              <option value="writable">Writable</option>
            </SelectInput>
          )}
        </Field>
        <Field label="Sync every" hint="Incremental: only what changed. 0 turns the periodic sync off.">
          {(fid, by) => <NumberInput id={fid} describedBy={by} value={s.sync_interval_minutes} min={0} max={10080} unit="min" disabled={!editable} onValue={(v) => v !== null && set({ sync_interval_minutes: v })} />}
        </Field>
        <Field label="Full sync every">
          {(fid) => <NumberInput id={fid} value={s.full_sync_interval_hours} min={1} max={720} unit="h" disabled={!editable} onValue={(v) => v !== null && set({ full_sync_interval_hours: v })} />}
        </Field>
        <div className="sm:col-span-2 flex flex-col gap-2">
          <p className="text-[0.8125rem] text-muted" aria-live="polite">
            {status}
          </p>
          {(lastSync ?? ldap.last_sync_stats) && (
            <p className="text-[0.8125rem] text-muted">
              <StatsLine stats={(lastSync ?? ldap.last_sync_stats) as LdapSyncStats} />
            </p>
          )}
          {editable && (
            <div className="flex flex-wrap gap-2">
              <Button disabled={sync.isPending} onClick={() => sync.mutate(false)}>
                <RefreshCw className="size-4" aria-hidden />
                {sync.isPending ? "Syncing…" : "Sync now"}
              </Button>
              <Button disabled={sync.isPending} onClick={() => sync.mutate(true)}>
                Full sync
              </Button>
            </div>
          )}
          <ErrorLine error={sync.error} />
        </div>
      </Section>
    </>
  );
}
