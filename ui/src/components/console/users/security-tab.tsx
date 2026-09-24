"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { Field, SelectInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, Row } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useConsole } from "@/lib/console/session";
import { type UserDetail as Detail } from "@/lib/console/users";
import { type Revealed } from "../clients/reveal";
import { LinkedIdentities } from "./identities";
import { PersonalTokens } from "./tokens";

/** Display names of `credentials.type` values. */
export const CREDENTIAL_KINDS: Record<string, string> = {
  totp: "Authenticator app",
  webauthn: "Passkey",
  recovery_code: "Recovery codes",
  password: "Password",
  email_otp: "Email code",
  sms_otp: "SMS code",
};

export function SecurityTab({ tenant, u, editable, onReveal, onChanged, onForce }: { tenant: string; u: Detail; editable: boolean; onReveal: (r: Revealed) => void; onChanged: () => unknown; onForce: () => void }) {
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
          <p className="text-[0.875rem] text-muted">None enrolled. Users add an authenticator app or a passkey when the sign-in policy asks for one.</p>
        ) : (
          <ul className="divide-y divide-line">
            {creds.data.credentials.map((c) => (
              <li key={c.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
                <span>
                  <span className="font-medium text-ink">{CREDENTIAL_KINDS[c.kind] ?? c.kind}</span>
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
        <LinkedIdentities tenant={tenant} id={u.id} editable={editable} />
        <PersonalTokens tenant={tenant} id={u.id} editable={editable} />
      </Card>
    </div>
  );
}
