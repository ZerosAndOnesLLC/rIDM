"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useMemo, useState } from "react";
import { Field, SaveIndicator, Section, SelectInput, TextInput, Toggle } from "@/components/console/form";
import { Card, Row } from "@/components/console/ui";
import { displayName, formatDate } from "@/i18n";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useConsole } from "@/lib/console/session";
import { type UserDetail as Detail, type UserUpdate } from "@/lib/console/users";
import { AttributeField, JsonInput } from "./attributes";

export type Draft = Pick<Detail, "username" | "email" | "email_verified" | "phone" | "phone_verified" | "locale" | "must_change_password"> & { attributes: Record<string, unknown> };

export function draftOf(u: Detail): Draft {
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

export function ProfileTab({ tenant, u, editable }: { tenant: string; u: Detail; editable: boolean }) {
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
