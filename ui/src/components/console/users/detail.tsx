"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Trash2, Unlock } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useMemo, useState } from "react";
import { Field, SaveIndicator, Section, SelectInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, IconButton, Modal, PageHeader, Row } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { displayName, formatDate } from "@/i18n";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useConsole } from "@/lib/console/session";
import { STATUS_LABELS, TABS, TAB_LABELS, describeAgent, roleName, statusTone, userHref, type Tab, type UserDetail as Detail, type UserUpdate } from "@/lib/console/users";
import { RevealModal, type Revealed } from "../clients/reveal";
import { AttributeField, JsonInput } from "./attributes";
import { useRolesAndGroups } from "./invite";

export function UserDetail({ tenant, id, tab }: { tenant: string; id: string; tab: Tab }) {
  const { client: api, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const editable = can("ridm:users:write");
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const query = useQuery({
    queryKey: ["user", tenant, id],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const reload = useCallback(() => qc.invalidateQueries({ queryKey: ["user", tenant, id] }), [qc, tenant, id]);
  const act = useMutation({
    mutationFn: async (what: "disable" | "enable" | "unlock" | "force" | "delete") => {
      const path = { slug: tenant, user: id };
      const r =
        what === "unlock"
          ? await api.POST("/admin/tenants/{slug}/users/{user}/unlock", { params: { path } })
          : what === "force"
            ? await api.POST("/admin/tenants/{slug}/users/{user}/force-password-change", { params: { path } })
            : what === "delete"
              ? await api.DELETE("/admin/tenants/{slug}/users/{user}", { params: { path } })
              : await api.PATCH("/admin/tenants/{slug}/users/{user}", { params: { path }, body: { status: what === "disable" ? "disabled" : "active" } as UserUpdate });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
      return what;
    },
    onSuccess: (what) => {
      void qc.invalidateQueries({ queryKey: ["users", tenant] });
      if (what === "delete") router.push(`/console/users/?tenant=${encodeURIComponent(tenant)}`);
      else void reload();
    },
  });
  const [confirmDelete, setConfirmDelete] = useState(false);

  if (query.isError) {
    return (
      <>
        <PageHeader title="User" />
        <p role="alert" className="text-[0.9rem] text-danger">
          {query.error.message}
        </p>
      </>
    );
  }
  if (!query.data) return <Spinner label="Loading user…" />;
  const u = query.data;
  const locked = u.status === "locked" || (u.locked_until !== null && u.locked_until !== undefined && new Date(u.locked_until) > new Date());

  return (
    <>
      <PageHeader
        title={u.username}
        sub={
          <span className="inline-flex flex-wrap items-center gap-2">
            {u.email && <span>{u.email}</span>}
            <Badge tone={statusTone(u.status)}>{STATUS_LABELS[u.status]}</Badge>
            {locked && <Badge tone="accent">Locked</Badge>}
            {u.must_change_password && <Badge>Must change password</Badge>}
          </span>
        }
        actions={
          editable ? (
            <>
              {locked && (
                <Button disabled={act.isPending} onClick={() => act.mutate("unlock")}>
                  <Unlock className="size-4" aria-hidden />
                  Unlock
                </Button>
              )}
              <Button disabled={act.isPending} onClick={() => act.mutate(u.status === "disabled" ? "enable" : "disable")}>
                {u.status === "disabled" ? "Enable" : "Disable"}
              </Button>
              <IconButton label="Delete user" onClick={() => setConfirmDelete(true)} className="text-danger hover:bg-danger-soft">
                <Trash2 className="size-4" aria-hidden />
              </IconButton>
            </>
          ) : undefined
        }
      />
      {act.isError && (
        <p role="alert" className="mb-3 text-[0.875rem] text-danger">
          {act.error.message}
        </p>
      )}
      <p className="mb-4 text-[0.8125rem] text-muted">
        <Link href={`/console/users/?tenant=${encodeURIComponent(tenant)}`} className="text-link underline underline-offset-4">
          All users
        </Link>
      </p>
      <nav aria-label="User sections" className="mb-5 flex flex-wrap gap-1 border-b border-line">
        {TABS.map((t) => (
          <Link
            key={t}
            href={userHref(tenant, id, t)}
            aria-current={t === tab ? "page" : undefined}
            className={`-mb-px border-b-2 px-3 py-2 text-[0.875rem] ${t === tab ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}
          >
            {TAB_LABELS[t]}
          </Link>
        ))}
      </nav>
      {tab === "profile" && <ProfileTab tenant={tenant} u={u} editable={editable} />}
      {tab === "security" && <SecurityTab tenant={tenant} u={u} editable={editable} onReveal={setRevealed} onChanged={reload} onForce={() => act.mutate("force")} />}
      {tab === "sessions" && <SessionsTab tenant={tenant} id={id} editable={editable} />}
      {tab === "roles" && <RolesTab tenant={tenant} id={id} editable={editable} />}
      {tab === "groups" && <GroupsTab tenant={tenant} id={id} editable={editable} />}
      {tab === "consents" && <ConsentsTab tenant={tenant} id={id} editable={editable} />}
      {tab === "audit" && <AuditTab tenant={tenant} id={id} />}
      <RevealModal revealed={revealed} onClose={() => setRevealed(null)} />
      <Modal open={confirmDelete} onOpenChange={setConfirmDelete} title={`Delete ${u.username}?`} description="The account is soft-deleted: sessions and devices end at once; it can be purged later.">
        <div className="flex justify-end gap-2 px-5 pb-5 pt-3">
          <Button onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button variant="danger" disabled={act.isPending} onClick={() => act.mutate("delete")}>
            Delete user
          </Button>
        </div>
      </Modal>
    </>
  );
}

type Draft = Pick<Detail, "username" | "email" | "email_verified" | "phone" | "phone_verified" | "locale" | "must_change_password"> & { attributes: Record<string, unknown> };

function draftOf(u: Detail): Draft {
  return {
    username: u.username,
    email: u.email ?? null,
    email_verified: u.email_verified,
    phone: u.phone ?? null,
    phone_verified: u.phone_verified,
    locale: u.locale ?? null,
    must_change_password: u.must_change_password,
    attributes: (u.attributes && typeof u.attributes === "object" ? (u.attributes as Record<string, unknown>) : {}) ?? {},
  };
}

function ProfileTab({ tenant, u, editable }: { tenant: string; u: Detail; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const schema = useQuery({
    queryKey: ["profile-schema", tenant],
    staleTime: 60_000,
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/profile-schema", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<Draft>(() => draftOf(u));
  const [seen, setSeen] = useState(u.updated_at);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setSeen(u.updated_at);
    setDraft(draftOf(u));
  } else if (seen !== u.updated_at && resetCount === seenReset) {
    // Another action (unlock, status) refreshed the user; keep local edits unless nothing was typed.
    setSeen(u.updated_at);
  }
  const save = useCallback(
    async (patch: Partial<Draft>, { keepalive }: SaveOptions) => {
      const { data, error } = await api.PATCH("/admin/tenants/{slug}/users/{user}", { params: { path: { slug: tenant, user: u.id } }, body: patch as UserUpdate, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["user", tenant, u.id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["user", tenant, u.id], (old: Detail | undefined) => (old ? { ...old, ...data } : old));
      void qc.invalidateQueries({ queryKey: ["users", tenant] });
    },
    [api, qc, tenant, u.id],
  );
  const { queue, status, error } = useAutoSave<Partial<Draft>>(save);
  const update = useCallback(
    (patch: Partial<Draft>) => {
      setDraft((d) => ({ ...d, ...patch }));
      if (editable) queue(patch);
    },
    [editable, queue],
  );
  const setAttr = useCallback(
    (name: string, value: unknown) => {
      setDraft((d) => {
        const attributes = { ...d.attributes };
        if (value === null || value === undefined) delete attributes[name];
        else attributes[name] = value;
        if (editable) queue({ attributes });
        return { ...d, attributes };
      });
    },
    [editable, queue],
  );
  const defs = useMemo(() => [...(schema.data?.attributes ?? [])].sort((a, b) => a.order - b.order || a.name.localeCompare(b.name)), [schema.data]);
  const declared = new Set(defs.map((d) => d.name));
  const others = Object.fromEntries(Object.entries(draft.attributes).filter(([k]) => !declared.has(k)));

  return (
    <div className="flex flex-col gap-6">
      <div className="flex justify-end">
        <SaveIndicator status={status} error={error} />
      </div>
      <Section id="identity" title="Identity" description="How the user signs in and is reached.">
        <Field label="Username">{(fid) => <TextInput id={fid} value={draft.username} disabled={!editable} autoCapitalize="none" onChange={(e) => update({ username: e.target.value })} />}</Field>
        <Field label="Preferred language">
          {(fid) => (
            <SelectInput id={fid} value={draft.locale ?? ""} disabled={!editable} onChange={(e) => update({ locale: e.target.value || null })}>
              <option value="">Tenant default</option>
              {["en", "de", "fr", "es", "it", "pt-BR", "nl", "ja", "zh-CN", "ar", "he"].map((l) => (
                <option key={l} value={l}>
                  {displayName(l)} ({l})
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
        <Field label="Email">{(fid) => <TextInput id={fid} type="email" value={draft.email ?? ""} disabled={!editable} onChange={(e) => update({ email: e.target.value || null })} />}</Field>
        <div className="flex items-end">
          <div className="w-full">
            <Toggle label="Email verified" checked={draft.email_verified} disabled={!editable || !draft.email} onChange={(v) => update({ email_verified: v })} />
          </div>
        </div>
        <Field label="Phone">{(fid) => <TextInput id={fid} type="tel" value={draft.phone ?? ""} disabled={!editable} onChange={(e) => update({ phone: e.target.value || null })} />}</Field>
        <div className="flex items-end">
          <div className="w-full">
            <Toggle label="Phone verified" checked={draft.phone_verified} disabled={!editable || !draft.phone} onChange={(v) => update({ phone_verified: v })} />
          </div>
        </div>
        <div className="sm:col-span-2">
          <Toggle label="Must change password at next sign-in" checked={draft.must_change_password} disabled={!editable} onChange={(v) => update({ must_change_password: v })} />
        </div>
      </Section>
      <Section id="attributes" title="Profile attributes" description={defs.length ? "As declared in the tenant's profile schema." : "The tenant's profile schema declares no attributes yet."}>
        {schema.isError && (
          <p role="alert" className="text-[0.875rem] text-danger sm:col-span-2">
            {schema.error.message}
          </p>
        )}
        {defs.map((def) => (
          <AttributeField key={def.name} def={def} value={draft.attributes[def.name]} onChange={(v) => setAttr(def.name, v)} disabled={!editable} />
        ))}
        {(schema.data?.allow_undeclared || Object.keys(others).length > 0) && (
          <Field label="Other attributes" hint={schema.data?.allow_undeclared ? "Undeclared attributes, stored verbatim (JSON object)." : "Present on the user but no longer declared."} wide>
            {(fid, by) => (
              <JsonInput
                id={fid}
                describedBy={by}
                value={Object.keys(others).length ? others : null}
                disabled={!editable}
                onChange={(v) => {
                  const next = v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
                  setDraft((d) => {
                    const kept = Object.fromEntries(Object.entries(d.attributes).filter(([k]) => declared.has(k)));
                    const attributes = { ...kept, ...next };
                    if (editable) queue({ attributes });
                    return { ...d, attributes };
                  });
                }}
              />
            )}
          </Field>
        )}
      </Section>
      <Card title="Record">
        <dl>
          <Row label="User ID">
            <code className="font-mono text-[0.8125rem]">{u.id}</code>
          </Row>
          <Row label="Created">{formatDate("en", u.created_at)}</Row>
          <Row label="Last sign-in">{u.last_login_at ? formatDate("en", u.last_login_at) : "Never"}</Row>
          <Row label="Terms accepted">{u.terms_accepted_at ? formatDate("en", u.terms_accepted_at) : "—"}</Row>
          <Row label="Failed attempts">{u.failed_attempts}</Row>
        </dl>
      </Card>
    </div>
  );
}

function SecurityTab({ tenant, u, editable, onReveal, onChanged, onForce }: { tenant: string; u: Detail; editable: boolean; onReveal: (r: Revealed) => void; onChanged: () => unknown; onForce: () => void }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const [mode, setMode] = useState<"temporary" | "set">("temporary");
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(true);
  const [notify, setNotify] = useState(true);
  const [revoke, setRevoke] = useState(true);
  const [skipPolicy, setSkipPolicy] = useState(false);
  const creds = useQuery({
    queryKey: ["user", tenant, u.id, "credentials"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/credentials", { params: { path: { slug: tenant, user: u.id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const setPw = useMutation({
    mutationFn: async () => {
      const { data, error } = await api.PUT("/admin/tenants/{slug}/users/{user}/password", {
        params: { path: { slug: tenant, user: u.id } },
        body: { password: mode === "set" ? password : null, must_change: mustChange, notify, revoke_sessions: revoke, skip_policy: skipPolicy },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (data) => {
      setPassword("");
      void onChanged();
      void qc.invalidateQueries({ queryKey: ["user", tenant, u.id, "credentials"] });
      if (data?.temporary_password) onReveal({ title: "Temporary password", description: `Hand it to ${u.username}; it must be changed at the next sign-in.`, values: [{ label: "Temporary password", value: data.temporary_password }] });
    },
  });
  const removeCred = useMutation({
    mutationFn: async (credId: string) => {
      const { error } = await api.DELETE("/admin/tenants/{slug}/users/{user}/credentials/{credential_id}", { params: { path: { slug: tenant, user: u.id, credential_id: credId } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["user", tenant, u.id, "credentials"] }),
  });
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Password">
        <dl className="mb-4">
          <Row label="Set">{u.password.set ? <Badge tone="ok">Yes</Badge> : <Badge>No password</Badge>}</Row>
          <Row label="Algorithm">{u.password.algorithm ?? "—"}</Row>
          <Row label="Changed">{u.password.changed_at ? formatDate("en", u.password.changed_at) : "—"}</Row>
          <Row label="Expires">{u.password.expires_at ? formatDate("en", u.password.expires_at) : "Never"}</Row>
          <Row label="Change required">{u.password.must_change ? <Badge tone="accent">At next sign-in</Badge> : "No"}</Row>
        </dl>
        {editable && (
          <form
            className="flex flex-col gap-3 border-t border-line pt-4"
            onSubmit={(e) => {
              e.preventDefault();
              setPw.mutate();
            }}
          >
            <Field label="Replace the password">
              {(fid) => (
                <SelectInput id={fid} value={mode} onChange={(e) => setMode(e.target.value as "temporary" | "set")}>
                  <option value="temporary">Generate a temporary password (shown once)</option>
                  <option value="set">Set a specific password</option>
                </SelectInput>
              )}
            </Field>
            {mode === "set" && <Field label="New password">{(fid) => <TextInput id={fid} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required />}</Field>}
            {mode === "set" && <Toggle label="Require a change at next sign-in" checked={mustChange} onChange={setMustChange} />}
            {mode === "set" && <Toggle label="Skip the password policy" hint="Also skips the history check." checked={skipPolicy} onChange={setSkipPolicy} />}
            <Toggle label="Notify the user by email" checked={notify} onChange={setNotify} />
            <Toggle label="Sign the user out everywhere" checked={revoke} onChange={setRevoke} />
            {setPw.isError && (
              <p role="alert" className="text-[0.875rem] text-danger">
                {setPw.error.message}
              </p>
            )}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="primary" disabled={setPw.isPending || (mode === "set" && !password)}>
                <KeyRound className="size-4" aria-hidden />
                {mode === "temporary" ? "Generate" : "Set password"}
              </Button>
              {!u.password.must_change && (
                <Button onClick={onForce}>Require a change at next sign-in</Button>
              )}
            </div>
          </form>
        )}
      </Card>
      <Card title="Second factors & passkeys">
        {creds.isPending ? (
          <Spinner label="Loading…" />
        ) : creds.isError ? (
          <p role="alert" className="text-[0.875rem] text-danger">
            {creds.error.message}
          </p>
        ) : creds.data.credentials.length === 0 ? (
          <p className="text-[0.875rem] text-muted">None enrolled. Users add an authenticator app when the sign-in policy asks for one.</p>
        ) : (
          <ul className="divide-y divide-line">
            {creds.data.credentials.map((c) => (
              <li key={c.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                <span>
                  <span className="font-medium text-ink">{c.kind}</span>
                  {c.label && <span className="ms-2 text-muted">{c.label}</span>}
                  <span className="block text-[0.8125rem] text-muted">
                    Added {formatDate("en", c.created_at)}
                    {c.last_used_at ? ` · used ${formatDate("en", c.last_used_at)}` : ""}
                  </span>
                </span>
                {editable && (
                  <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={removeCred.isPending} onClick={() => removeCred.mutate(c.id)}>
                    Remove
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
        {removeCred.isError && (
          <p role="alert" className="mt-2 text-[0.875rem] text-danger">
            {removeCred.error.message}
          </p>
        )}
        <p className="mt-4 border-t border-line pt-3 text-[0.8125rem] text-muted">Personal access tokens (Phase 8.5) and linked identities (Phase 8.3) will appear here.</p>
      </Card>
    </div>
  );
}

function SessionsTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const path = { slug: tenant, user: id };
  const sessions = useQuery({
    queryKey: ["user", tenant, id, "sessions"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/sessions", { params: { path } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const devices = useQuery({
    queryKey: ["user", tenant, id, "devices"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/devices", { params: { path } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const revoke = useMutation({
    mutationFn: async (what: { kind: "session" | "device"; id?: string }) => {
      const r =
        what.kind === "session"
          ? what.id
            ? await api.DELETE("/admin/tenants/{slug}/users/{user}/sessions/{session_id}", { params: { path: { ...path, session_id: what.id } } })
            : await api.DELETE("/admin/tenants/{slug}/users/{user}/sessions", { params: { path } })
          : what.id
            ? await api.DELETE("/admin/tenants/{slug}/users/{user}/devices/{device_id}", { params: { path: { ...path, device_id: what.id } } })
            : await api.DELETE("/admin/tenants/{slug}/users/{user}/devices", { params: { path } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["user", tenant, id, "sessions"] });
      void qc.invalidateQueries({ queryKey: ["user", tenant, id, "devices"] });
    },
  });
  return (
    <div className="flex flex-col gap-4">
      {revoke.isError && (
        <p role="alert" className="text-[0.875rem] text-danger">
          {revoke.error.message}
        </p>
      )}
      <Card
        title="Sessions"
        actions={
          editable && (sessions.data?.length ?? 0) > 0 ? (
            <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "session" })}>
              Sign out everywhere
            </Button>
          ) : undefined
        }
      >
        {sessions.isPending ? (
          <Spinner label="Loading…" />
        ) : sessions.isError ? (
          <p role="alert" className="text-[0.875rem] text-danger">
            {sessions.error.message}
          </p>
        ) : sessions.data.length === 0 ? (
          <p className="text-[0.875rem] text-muted">No live sessions.</p>
        ) : (
          <ul className="divide-y divide-line">
            {sessions.data.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                <span>
                  <span className="font-medium text-ink">{describeAgent(s.user_agent)}</span>
                  <span className="ms-2 text-muted">{s.ip ?? ""}</span>
                  <span className="block text-[0.8125rem] text-muted">
                    Signed in {formatDate("en", s.auth_time)} · {s.amr.join(", ")} · last seen {formatDate("en", s.last_seen_at)} · ends {formatDate("en", s.expires_at)}
                  </span>
                </span>
                {editable && (
                  <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "session", id: s.id })}>
                    Revoke
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card
        title="Trusted devices"
        actions={
          editable && (devices.data?.length ?? 0) > 0 ? (
            <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "device" })}>
              Forget all
            </Button>
          ) : undefined
        }
      >
        {devices.isPending ? (
          <Spinner label="Loading…" />
        ) : devices.isError ? (
          <p role="alert" className="text-[0.875rem] text-danger">
            {devices.error.message}
          </p>
        ) : devices.data.length === 0 ? (
          <p className="text-[0.875rem] text-muted">No remembered devices.</p>
        ) : (
          <ul className="divide-y divide-line">
            {devices.data.map((d) => (
              <li key={d.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                <span>
                  <span className="font-medium text-ink">{d.name ?? describeAgent(d.user_agent)}</span>
                  <span className="ms-2 text-muted">{d.ip ?? ""}</span>
                  <span className="block text-[0.8125rem] text-muted">
                    Remembered {formatDate("en", d.created_at)} · last seen {formatDate("en", d.last_seen_at)} · until {formatDate("en", d.expires_at)}
                  </span>
                </span>
                {editable && (
                  <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate({ kind: "device", id: d.id })}>
                    Forget
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function RolesTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const { roles: all } = useRolesAndGroups(tenant);
  const [pick, setPick] = useState("");
  const mine = useQuery({
    queryKey: ["user", tenant, id, "roles"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/roles", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await api.PUT("/admin/tenants/{slug}/users/{user}/roles/{role_id}", { params: { path: { slug: tenant, user: id, role_id: what.add } } })
        : await api.DELETE("/admin/tenants/{slug}/users/{user}/roles/{role_id}", { params: { path: { slug: tenant, user: id, role_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      setPick("");
      void qc.invalidateQueries({ queryKey: ["user", tenant, id] });
    },
  });
  const directIds = new Set(mine.data?.direct.map((r) => r.id) ?? []);
  const options = (all.data ?? []).filter((r) => !directIds.has(r.id));
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Assigned directly">
        {mine.isPending ? (
          <Spinner label="Loading…" />
        ) : mine.isError ? (
          <p role="alert" className="text-[0.875rem] text-danger">
            {mine.error.message}
          </p>
        ) : (
          <>
            {mine.data.direct.length === 0 && <p className="text-[0.875rem] text-muted">No direct roles.</p>}
            <ul className="divide-y divide-line">
              {mine.data.direct.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                  <span>
                    <span className="font-medium text-ink">{roleName(r)}</span>
                    {r.built_in && <Badge>built-in</Badge>}
                    {r.description && <span className="block text-[0.8125rem] text-muted">{r.description}</span>}
                  </span>
                  {editable && (
                    <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={change.isPending} onClick={() => change.mutate({ remove: r.id })}>
                      Remove
                    </Button>
                  )}
                </li>
              ))}
            </ul>
            {editable && (
              <form
                className="mt-4 flex gap-2 border-t border-line pt-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (pick) change.mutate({ add: pick });
                }}
              >
                <SelectInput aria-label="Role to assign" value={pick} onChange={(e) => setPick(e.target.value)}>
                  <option value="">Choose a role…</option>
                  {options.map((r) => (
                    <option key={r.id} value={r.id}>
                      {roleName(r)}
                    </option>
                  ))}
                </SelectInput>
                <Button type="submit" variant="primary" disabled={!pick || change.isPending}>
                  Assign
                </Button>
              </form>
            )}
            {change.isError && (
              <p role="alert" className="mt-2 text-[0.875rem] text-danger">
                {change.error.message}
              </p>
            )}
          </>
        )}
      </Card>
      <Card title="Effective roles">
        <p className="mb-2 text-[0.8125rem] text-muted">Direct roles plus those inherited through groups and composites.</p>
        <div className="flex flex-wrap gap-1.5">
          {mine.data?.effective.map((r) => (
            <Badge key={r.id} tone={directIds.has(r.id) ? "accent" : "neutral"}>
              {roleName(r)}
            </Badge>
          ))}
          {mine.data?.effective.length === 0 && <span className="text-[0.875rem] text-muted">None.</span>}
        </div>
      </Card>
    </div>
  );
}

function GroupsTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const { groups: all } = useRolesAndGroups(tenant);
  const [pick, setPick] = useState("");
  const mine = useQuery({
    queryKey: ["user", tenant, id, "groups"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/groups", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await api.PUT("/admin/tenants/{slug}/users/{user}/groups/{group_id}", { params: { path: { slug: tenant, user: id, group_id: what.add } } })
        : await api.DELETE("/admin/tenants/{slug}/users/{user}/groups/{group_id}", { params: { path: { slug: tenant, user: id, group_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      setPick("");
      void qc.invalidateQueries({ queryKey: ["user", tenant, id] });
    },
  });
  const directIds = new Set(mine.data?.direct.map((g) => g.id) ?? []);
  const byId = new Map((all.data ?? []).map((g) => [g.id, g]));
  const pathOf = (gid: string): string => {
    const g = byId.get(gid);
    if (!g) return gid;
    return g.parent_id ? `${pathOf(g.parent_id)} / ${g.name}` : g.name;
  };
  const options = (all.data ?? []).filter((g) => !directIds.has(g.id)).map((g) => ({ id: g.id, label: pathOf(g.id) })).sort((a, b) => a.label.localeCompare(b.label));
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Member of">
        {mine.isPending ? (
          <Spinner label="Loading…" />
        ) : mine.isError ? (
          <p role="alert" className="text-[0.875rem] text-danger">
            {mine.error.message}
          </p>
        ) : (
          <>
            {mine.data.direct.length === 0 && <p className="text-[0.875rem] text-muted">No groups.</p>}
            <ul className="divide-y divide-line">
              {mine.data.direct.map((g) => (
                <li key={g.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                  <span className="font-medium text-ink">{pathOf(g.id)}</span>
                  {editable && (
                    <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={change.isPending} onClick={() => change.mutate({ remove: g.id })}>
                      Leave
                    </Button>
                  )}
                </li>
              ))}
            </ul>
            {editable && (
              <form
                className="mt-4 flex gap-2 border-t border-line pt-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (pick) change.mutate({ add: pick });
                }}
              >
                <SelectInput aria-label="Group to join" value={pick} onChange={(e) => setPick(e.target.value)}>
                  <option value="">Choose a group…</option>
                  {options.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.label}
                    </option>
                  ))}
                </SelectInput>
                <Button type="submit" variant="primary" disabled={!pick || change.isPending}>
                  Join
                </Button>
              </form>
            )}
            {change.isError && (
              <p role="alert" className="mt-2 text-[0.875rem] text-danger">
                {change.error.message}
              </p>
            )}
          </>
        )}
      </Card>
      <Card title="Effective groups">
        <p className="mb-2 text-[0.8125rem] text-muted">Direct memberships plus their ancestors.</p>
        <div className="flex flex-wrap gap-1.5">
          {mine.data?.effective.map((g) => (
            <Badge key={g.id} tone={directIds.has(g.id) ? "accent" : "neutral"}>
              {pathOf(g.id)}
            </Badge>
          ))}
          {mine.data?.effective.length === 0 && <span className="text-[0.875rem] text-muted">None.</span>}
        </div>
      </Card>
    </div>
  );
}

function ConsentsTab({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const consents = useQuery({
    queryKey: ["user", tenant, id, "consents"],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/consents", { params: { path: { slug: tenant, user: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      const names: Record<string, string> = {};
      await Promise.all(
        data.map(async (c) => {
          const r = await api.GET("/admin/tenants/{slug}/clients/{client}", { params: { path: { slug: tenant, client: c.client_id } } });
          if (r.data) names[c.client_id] = `${r.data.name} (${r.data.client_id})`;
        }),
      );
      return { consents: data, names };
    },
  });
  const revoke = useMutation({
    mutationFn: async (clientId: string) => {
      const { error } = await api.DELETE("/admin/tenants/{slug}/users/{user}/consents/{client_id}", { params: { path: { slug: tenant, user: id, client_id: clientId } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["user", tenant, id, "consents"] }),
  });
  return (
    <Card title="Consented applications">
      {consents.isPending ? (
        <Spinner label="Loading…" />
      ) : consents.isError ? (
        <p role="alert" className="text-[0.875rem] text-danger">
          {consents.error.message}
        </p>
      ) : consents.data.consents.length === 0 ? (
        <p className="text-[0.875rem] text-muted">No consents recorded.</p>
      ) : (
        <ul className="divide-y divide-line">
          {consents.data.consents.map((c) => (
            <li key={c.client_id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
              <span>
                <span className="font-medium text-ink">{consents.data.names[c.client_id] ?? c.client_id}</span>
                <span className="block text-[0.8125rem] text-muted">
                  {c.scopes.join(" ")} · granted {formatDate("en", c.granted_at)}
                  {c.revoked_at ? ` · revoked ${formatDate("en", c.revoked_at)}` : ""}
                </span>
              </span>
              {editable && !c.revoked_at && (
                <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate(c.client_id)}>
                  Revoke
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {revoke.isError && (
        <p role="alert" className="mt-2 text-[0.875rem] text-danger">
          {revoke.error.message}
        </p>
      )}
    </Card>
  );
}

function AuditTab({ tenant, id }: { tenant: string; id: string }) {
  const { client: api, can } = useConsole();
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [open, setOpen] = useState<string | null>(null);
  const page = useQuery({
    queryKey: ["user", tenant, id, "audit", cursor],
    enabled: can("ridm:audit:read"),
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/users/{user}/audit", { params: { path: { slug: tenant, user: id }, query: { cursor, limit: 50 } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  if (!can("ridm:audit:read")) return <p className="text-[0.875rem] text-muted">You need audit access to see this.</p>;
  return (
    <Card title="Audit trail">
      {page.isPending ? (
        <Spinner label="Loading…" />
      ) : page.isError ? (
        <p role="alert" className="text-[0.875rem] text-danger">
          {page.error.message}
        </p>
      ) : page.data.items.length === 0 ? (
        <p className="text-[0.875rem] text-muted">Nothing recorded yet.</p>
      ) : (
        <ul className="divide-y divide-line">
          {page.data.items.map((e) => (
            <li key={e.id} className="py-2 text-[0.875rem]">
              <button type="button" onClick={() => setOpen(open === e.id ? null : e.id)} aria-expanded={open === e.id} className="flex w-full items-center justify-between gap-3 text-start">
                <span>
                  <span className="font-mono text-[0.8125rem] font-medium text-ink">{e.name}</span>
                  <span className="ms-2 text-muted">by {e.actor_type}</span>
                </span>
                <span className="shrink-0 text-[0.8125rem] text-muted">{formatDate("en", e.occurred_at)}</span>
              </button>
              {open === e.id && (
                <pre tabIndex={0} aria-label="Event payload" className="mt-2 max-h-64 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-[0.8125rem] text-ink">
                  {JSON.stringify({ ip: e.ip, user_agent: e.user_agent, payload: e.payload }, null, 2)}
                </pre>
              )}
            </li>
          ))}
        </ul>
      )}
      {page.data?.next_cursor && (
        <div className="mt-3 text-center">
          <Button onClick={() => setCursor(page.data.next_cursor ?? undefined)}>Older events</Button>
        </div>
      )}
    </Card>
  );
}
