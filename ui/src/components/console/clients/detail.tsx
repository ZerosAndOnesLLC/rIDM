"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FlaskConical, KeyRound, RotateCw, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useMemo, useState } from "react";
import { Field, NumberInput, SaveIndicator, Section, SelectInput, TagsInput, TextArea, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, IconButton, Modal, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { ALL_GRANTS, AUTH_METHODS, GRANT_LABELS, playgroundHref, typeLabel, usesSecret, type AuthMethod, type ClientView, type NewClient } from "@/lib/console/clients";
import { useConsole } from "@/lib/console/session";
import { AudiencePicker, CheckList, ScopePicker } from "./pickers";
import { CopyButton, RevealModal, type Revealed } from "./reveal";

type Patch = Partial<NewClient> & { status?: "active" | "disabled" };

const GRACE_OPTIONS = [
  { value: 0, label: "Retire the old secret now" },
  { value: 3600, label: "Keep the old secret for 1 hour" },
  { value: 86_400, label: "Keep the old secret for 24 hours" },
  { value: 7 * 86_400, label: "Keep the old secret for 7 days" },
];

export function ClientDetail({ tenant, id }: { tenant: string; id: string }) {
  const { client: api, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const editable = can("ridm:clients:write");
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const query = useQuery({
    queryKey: ["client", tenant, id],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/clients/{client}", { params: { path: { slug: tenant, client: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });

  const [draft, setDraft] = useState<ClientView | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);

  const save = useCallback(
    async (patch: Patch, { keepalive }: SaveOptions) => {
      const { data, error } = await api.PATCH("/admin/tenants/{slug}/clients/{client}", { params: { path: { slug: tenant, client: id } }, body: patch, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["client", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["client", tenant, id], data);
      void qc.invalidateQueries({ queryKey: ["clients", tenant] });
      if (data.client_secret) {
        setRevealed({
          title: "New client secret",
          description: "Switching to a secret-based method generated this secret.",
          values: [{ label: "Client secret", value: data.client_secret }],
        });
      }
    },
    [api, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave<Patch>(save);
  const update = useCallback(
    (patch: Patch) => {
      setDraft((d) => (d ? ({ ...d, ...patch } as ClientView) : d));
      if (editable) queue(patch);
    },
    [editable, queue],
  );

  const refresh = useCallback(
    (data: ClientView) => {
      qc.setQueryData(["client", tenant, id], data);
      setResetCount((n) => n + 1);
    },
    [qc, tenant, id],
  );

  const c = draft;
  const sections = useMemo(() => (c ? { c } : null), [c]);
  if (query.isError) {
    return (
      <>
        <PageHeader title="Client" />
        <p role="alert" className="text-[0.9rem] text-danger">
          {query.error.message}
        </p>
      </>
    );
  }
  if (!c || !sections) return <Spinner label="Loading client…" />;
  const grantsOk = !(c.token_endpoint_auth_method === "none" && c.allowed_grants.includes("client_credentials"));

  return (
    <>
      <PageHeader
        title={c.name}
        sub={
          <span className="inline-flex flex-wrap items-center gap-2">
            <code className="font-mono text-[0.8125rem]">{c.client_id}</code>
            <CopyButton value={c.client_id} label="Copy ID" />
            <Badge>{typeLabel(c.client_type)}</Badge>
            {c.status === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="danger">Disabled</Badge>}
          </span>
        }
        actions={
          <>
            <SaveIndicator status={status} error={error} />
            <Link href={playgroundHref(tenant, c.id)} className="inline-flex min-h-9 items-center gap-2 rounded-[var(--radius)] border border-line bg-paper px-3.5 text-[0.875rem] font-medium text-ink hover:bg-ground">
              <FlaskConical className="size-4" aria-hidden />
              Playground
            </Link>
          </>
        }
      />
      <p className="mb-4 text-[0.8125rem] text-muted">
        <Link href={`/console/clients/?tenant=${encodeURIComponent(tenant)}`} className="text-link underline underline-offset-4">
          All clients
        </Link>
      </p>
      <div className="flex flex-col gap-6">
        <Section id="basics" title="Basics" description="What users see on consent and login pages.">
          <Field label="Name">{(fid) => <TextInput id={fid} value={c.name} disabled={!editable} onChange={(e) => update({ name: e.target.value })} />}</Field>
          <Field label="Status" hint="A disabled client is refused at every endpoint.">
            {(fid, by) => (
              <SelectInput id={fid} aria-describedby={by} value={c.status} disabled={!editable} onChange={(e) => update({ status: e.target.value as "active" | "disabled" })}>
                <option value="active">Active</option>
                <option value="disabled">Disabled</option>
              </SelectInput>
            )}
          </Field>
          <Field label="Description" wide>
            {(fid) => <TextInput id={fid} value={c.description ?? ""} disabled={!editable} onChange={(e) => update({ description: e.target.value || null })} />}
          </Field>
          <Field label="Logo URI">{(fid) => <TextInput id={fid} type="url" value={c.logo_uri ?? ""} disabled={!editable} onChange={(e) => update({ logo_uri: e.target.value || null })} />}</Field>
          <Field label="Home page">{(fid) => <TextInput id={fid} type="url" value={c.client_uri ?? ""} disabled={!editable} onChange={(e) => update({ client_uri: e.target.value || null })} />}</Field>
          <Field label="Terms of service URI">{(fid) => <TextInput id={fid} type="url" value={c.tos_uri ?? ""} disabled={!editable} onChange={(e) => update({ tos_uri: e.target.value || null })} />}</Field>
          <Field label="Privacy policy URI">{(fid) => <TextInput id={fid} type="url" value={c.policy_uri ?? ""} disabled={!editable} onChange={(e) => update({ policy_uri: e.target.value || null })} />}</Field>
        </Section>

        <Section id="grants" title="Grants & authentication" description="How the client obtains tokens and proves who it is.">
          <CheckList legend="Grant types" options={ALL_GRANTS.map((g) => ({ value: g, label: GRANT_LABELS[g]! }))} value={c.allowed_grants} onChange={(v) => update({ allowed_grants: v })} disabled={!editable} />
          <div className="flex flex-col gap-4">
            <Field label="Client authentication" hint={usesSecret(c.token_endpoint_auth_method) ? "Secrets are managed below." : c.token_endpoint_auth_method === "private_key_jwt" ? "Needs a JWKS or JWKS URI (Tokens & keys)." : "Public client: no credential, PKCE required."} error={grantsOk ? null : "Client credentials need client authentication."}>
              {(fid, by) => (
                <SelectInput id={fid} aria-describedby={by} value={c.token_endpoint_auth_method} disabled={!editable} onChange={(e) => update({ token_endpoint_auth_method: e.target.value as AuthMethod })}>
                  {AUTH_METHODS.map((m) => (
                    <option key={m.value} value={m.value}>
                      {m.label}
                    </option>
                  ))}
                </SelectInput>
              )}
            </Field>
            <Toggle label="Require PKCE" checked={c.require_pkce} disabled={!editable} onChange={(v) => update({ require_pkce: v })} />
            <Toggle label="DPoP-bound access tokens" hint="Every token request must carry a DPoP proof; the tokens only work with that key (RFC 9449)." checked={c.dpop_bound_access_tokens} disabled={!editable} onChange={(v) => update({ dpop_bound_access_tokens: v })} />
            <Toggle label="Ask users for consent" hint="Off for first-party applications." checked={c.require_consent} disabled={!editable} onChange={(v) => update({ require_consent: v })} />
            <Toggle
              label="Scope claims in the ID token"
              hint="Repeat the profile, email, address and phone claims in the ID token. Off by default: with an access token issued they are read from the userinfo endpoint (OIDC Core 5.4)."
              checked={c.id_token_scope_claims}
              disabled={!editable}
              onChange={(v) => update({ id_token_scope_claims: v })}
            />
            <Field label="Subject identifier" hint="Pairwise subjects differ per sector so clients cannot correlate users.">
              {(fid, by) => (
                <SelectInput id={fid} aria-describedby={by} value={c.subject_type} disabled={!editable} onChange={(e) => update({ subject_type: e.target.value as "public" | "pairwise" })}>
                  <option value="public">Public</option>
                  <option value="pairwise">Pairwise</option>
                </SelectInput>
              )}
            </Field>
            {c.subject_type === "pairwise" && (
              <Field label="Sector identifier URI">{(fid) => <TextInput id={fid} type="url" value={c.sector_identifier_uri ?? ""} disabled={!editable} onChange={(e) => update({ sector_identifier_uri: e.target.value || null })} />}</Field>
            )}
          </div>
        </Section>

        <Section id="uris" title="URIs" description="Where the browser may be sent and which origins may call from a browser.">
          <Field label="Redirect URIs" hint="Exact matches; native clients may use loopback addresses." wide>
            {(fid, by) => <TagsInput id={fid} describedBy={by} value={c.redirect_uris} onChange={(v) => update({ redirect_uris: v })} placeholder="https://app.example.com/callback" />}
          </Field>
          <Field label="Post-logout redirect URIs" wide>
            {(fid) => <TagsInput id={fid} value={c.post_logout_redirect_uris} onChange={(v) => update({ post_logout_redirect_uris: v })} placeholder="https://app.example.com/" />}
          </Field>
          <Field label="CORS origins" hint="scheme://host[:port], no path." wide>
            {(fid, by) => <TagsInput id={fid} describedBy={by} value={c.cors_origins} onChange={(v) => update({ cors_origins: v })} placeholder="https://app.example.com" />}
          </Field>
          <Field label="Initiate login URI" hint="Third-party initiated login (OIDC Core §4).">
            {(fid, by) => <TextInput id={fid} aria-describedby={by} type="url" value={c.initiate_login_uri ?? ""} disabled={!editable} onChange={(e) => update({ initiate_login_uri: e.target.value || null })} />}
          </Field>
          <Field label="Back-channel logout URI" hint="Receives a logout token when the session ends.">
            {(fid, by) => <TextInput id={fid} aria-describedby={by} type="url" value={c.backchannel_logout_uri ?? ""} disabled={!editable} onChange={(e) => update({ backchannel_logout_uri: e.target.value || null })} />}
          </Field>
          <Field label="Front-channel logout URI" hint="Loaded in a frame on the sign-out page.">
            {(fid, by) => <TextInput id={fid} aria-describedby={by} type="url" value={c.frontchannel_logout_uri ?? ""} disabled={!editable} onChange={(e) => update({ frontchannel_logout_uri: e.target.value || null })} />}
          </Field>
        </Section>

        <Section id="access" title="Scopes & audiences" description="What the client may ask for.">
          <ScopePicker tenant={tenant} value={c.allowed_scopes} onChange={(v) => update({ allowed_scopes: v })} disabled={!editable} />
          <AudiencePicker tenant={tenant} value={c.allowed_audiences} onChange={(v) => update({ allowed_audiences: v })} disabled={!editable} />
        </Section>

        <TokensSection c={c} editable={editable} update={update} />

        {usesSecret(c.token_endpoint_auth_method) && <SecretsSection tenant={tenant} c={c} editable={editable} onReveal={setRevealed} onChanged={refresh} />}

        <ServiceAccountSection tenant={tenant} c={c} editable={editable} onChanged={refresh} />

        <Section id="management" title="Client management" description="Let the client's owner manage its own metadata through RFC 7592 without console access.">
          <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
            <RegistrationToken tenant={tenant} id={c.id} editable={editable} onReveal={setRevealed} />
            <span className="text-[0.8125rem] text-muted">Issuing a token replaces any previous one.</span>
          </div>
        </Section>

        {editable && c.client_id !== "ridm-admin-console" && <DeleteClient tenant={tenant} c={c} onDeleted={() => router.push(`/console/clients/?tenant=${encodeURIComponent(tenant)}`)} />}
      </div>
      <RevealModal revealed={revealed} onClose={() => setRevealed(null)} />
    </>
  );
}

function TokensSection({ c, editable, update }: { c: ClientView; editable: boolean; update: (p: Patch) => void }) {
  const [jwksText, setJwksText] = useState(c.jwks ? JSON.stringify(c.jwks, null, 2) : "");
  const [jwksError, setJwksError] = useState<string | null>(null);
  const enc = c.id_token_encryption;
  return (
    <Section id="tokens" title="Tokens & keys" description="Lifetimes override the tenant defaults; encryption and JWKS are for clients that need them.">
      <Field label="Access token lifetime" hint="Empty = tenant default.">
        {(fid, by) => <NumberInput id={fid} describedBy={by} value={c.access_token_ttl_secs ?? null} min={30} nullable onValue={(v) => update({ access_token_ttl_secs: v })} unit="s" />}
      </Field>
      <Field label="ID token lifetime" hint="Empty = tenant default.">
        {(fid, by) => <NumberInput id={fid} describedBy={by} value={c.id_token_ttl_secs ?? null} min={30} nullable onValue={(v) => update({ id_token_ttl_secs: v })} unit="s" />}
      </Field>
      <Field label="Refresh token lifetime" hint="Empty = tenant default.">
        {(fid, by) => <NumberInput id={fid} describedBy={by} value={c.refresh_token_ttl_secs ?? null} min={60} nullable onValue={(v) => update({ refresh_token_ttl_secs: v })} unit="s" />}
      </Field>
      <Field label="Access token format" hint="Opaque tokens carry no readable claims: APIs learn what they stand for from the introspection endpoint.">
        {(fid, by) => (
          <SelectInput id={fid} aria-describedby={by} value={c.access_token_format} disabled={!editable} onChange={(e) => update({ access_token_format: e.target.value as "jwt" | "opaque" })}>
            <option value="jwt">JWT</option>
            <option value="opaque">Opaque</option>
          </SelectInput>
        )}
      </Field>
      <Field label="ID token encryption" hint="Needs the client's JWKS or JWKS URI.">
        {(fid, by) => (
          <SelectInput
            id={fid}
            aria-describedby={by}
            value={enc ? `${enc.alg}/${enc.enc}` : ""}
            disabled={!editable}
            onChange={(e) => {
              const v = e.target.value;
              if (!v) update({ id_token_encryption: null });
              else {
                const [alg, encv] = v.split("/") as [string, string];
                update({ id_token_encryption: { alg, enc: encv } });
              }
            }}
          >
            <option value="">None</option>
            <option value="RSA-OAEP-256/A256GCM">RSA-OAEP-256 + A256GCM</option>
            <option value="RSA-OAEP-256/A128GCM">RSA-OAEP-256 + A128GCM</option>
            <option value="RSA-OAEP/A256GCM">RSA-OAEP + A256GCM</option>
          </SelectInput>
        )}
      </Field>
      <Field label="JWKS URI">{(fid) => <TextInput id={fid} type="url" value={c.jwks_uri ?? ""} disabled={!editable} onChange={(e) => update({ jwks_uri: e.target.value || null })} />}</Field>
      <Field label="JWKS (inline)" hint="A JSON Web Key Set; saved when it parses." error={jwksError} wide>
        {(fid, by) => (
          <TextArea
            id={fid}
            aria-describedby={by}
            value={jwksText}
            disabled={!editable}
            spellCheck={false}
            onChange={(e) => {
              const t = e.target.value;
              setJwksText(t);
              if (t.trim() === "") {
                setJwksError(null);
                update({ jwks: null });
                return;
              }
              try {
                const parsed = JSON.parse(t) as unknown;
                if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { keys?: unknown }).keys)) throw new Error("no keys");
                setJwksError(null);
                update({ jwks: parsed });
              } catch {
                setJwksError('Must be a JSON object with a "keys" array.');
              }
            }}
          />
        )}
      </Field>
    </Section>
  );
}

function SecretsSection({ tenant, c, editable, onReveal, onChanged }: { tenant: string; c: ClientView; editable: boolean; onReveal: (r: Revealed) => void; onChanged: (c: ClientView) => void }) {
  const { client: api } = useConsole();
  const [grace, setGrace] = useState(86_400);
  const rotate = useMutation({
    mutationFn: async () => {
      const { data, error } = await api.POST("/admin/tenants/{slug}/clients/{client}/secrets", { params: { path: { slug: tenant, client: c.id } }, body: { grace_secs: grace } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (data) => {
      onChanged(data);
      if (data.client_secret) onReveal({ title: "New client secret", description: "The previous secret keeps working for the grace period you chose.", values: [{ label: "Client secret", value: data.client_secret }] });
    },
  });
  const revoke = useMutation({
    mutationFn: async (secretId: string) => {
      const { data, error } = await api.DELETE("/admin/tenants/{slug}/clients/{client}/secrets/{secret_id}", { params: { path: { slug: tenant, client: c.id, secret_id: secretId } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: onChanged,
  });
  const err = rotate.error ?? revoke.error;
  return (
    <Section id="secrets" title="Secrets" description="Shown once when generated. Rotate with a grace period so a running deployment can switch over.">
      <div className="sm:col-span-2">
        <table className="w-full text-[0.875rem]">
          <thead className="text-[0.75rem] uppercase tracking-wide text-muted">
            <tr className="border-b border-line">
              <th scope="col" className="py-2 text-start font-medium">Secret</th>
              <th scope="col" className="py-2 text-start font-medium">Created</th>
              <th scope="col" className="py-2 text-start font-medium">Valid until</th>
              <th scope="col" className="py-2 text-end font-medium"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {c.secrets.length === 0 && (
              <tr>
                <td colSpan={4} className="py-4 text-center text-muted">No secret yet; generate one below.</td>
              </tr>
            )}
            {c.secrets.map((s) => (
              <tr key={s.id} className="border-b border-line last:border-b-0">
                <td className="py-2 font-mono text-[0.8125rem] text-muted">…{s.id.slice(-8)}</td>
                <td className="py-2 text-muted">{formatDate("en", s.created_at)}</td>
                <td className="py-2">{s.expires_at ? <Badge>Retiring {formatDate("en", s.expires_at)}</Badge> : <Badge tone="ok">Current</Badge>}</td>
                <td className="py-2 text-end">
                  {editable && c.secrets.length > 1 && (
                    <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={revoke.isPending} onClick={() => revoke.mutate(s.id)}>
                      Revoke
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {editable && (
        <div className="flex flex-wrap items-end gap-3 sm:col-span-2">
          <Field label="Grace period">
            {(fid) => (
              <SelectInput id={fid} value={grace} onChange={(e) => setGrace(Number(e.target.value))} className="min-w-[16rem]">
                {GRACE_OPTIONS.map((g) => (
                  <option key={g.value} value={g.value}>
                    {g.label}
                  </option>
                ))}
              </SelectInput>
            )}
          </Field>
          <Button variant="primary" disabled={rotate.isPending} onClick={() => rotate.mutate()}>
            <RotateCw className="size-4" aria-hidden />
            {c.secrets.length ? "Rotate secret" : "Generate secret"}
          </Button>
          {err && (
            <p role="alert" className="text-[0.875rem] text-danger">
              {err.message}
            </p>
          )}
        </div>
      )}
    </Section>
  );
}

function ServiceAccountSection({ tenant, c, editable, onChanged }: { tenant: string; c: ClientView; editable: boolean; onChanged: (c: ClientView) => void }) {
  const { client: api } = useConsole();
  const enable = useMutation({
    mutationFn: async () => {
      const { data, error } = await api.PUT("/admin/tenants/{slug}/clients/{client}/service-account", { params: { path: { slug: tenant, client: c.id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: onChanged,
  });
  const disable = useMutation({
    mutationFn: async () => {
      const { data, error } = await api.DELETE("/admin/tenants/{slug}/clients/{client}/service-account", { params: { path: { slug: tenant, client: c.id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: onChanged,
  });
  const canHave = c.allowed_grants.includes("client_credentials");
  const err = enable.error ?? disable.error;
  return (
    <Section id="service-account" title="Service account" description="A user the client acts as under client credentials, so it can hold roles and groups.">
      <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
        {c.service_account_user_id ? (
          <>
            <Badge tone="ok">Enabled</Badge>
            <Link href={`/console/users/?tenant=${encodeURIComponent(tenant)}&user=${c.service_account_user_id}`} className="text-[0.875rem] text-link underline underline-offset-4">
              svc-{c.client_id}
            </Link>
            {editable && (
              <Button variant="danger" disabled={disable.isPending} onClick={() => disable.mutate()}>
                Remove service account
              </Button>
            )}
          </>
        ) : (
          <>
            <Badge>Not enabled</Badge>
            {editable && (
              <Button disabled={!canHave || enable.isPending} onClick={() => enable.mutate()}>
                Enable service account
              </Button>
            )}
            {!canHave && <span className="text-[0.8125rem] text-muted">Needs the client credentials grant.</span>}
          </>
        )}
        {err && (
          <p role="alert" className="text-[0.875rem] text-danger">
            {err.message}
          </p>
        )}
      </div>
    </Section>
  );
}

function RegistrationToken({ tenant, id, editable, onReveal }: { tenant: string; id: string; editable: boolean; onReveal: (r: Revealed) => void }) {
  const { client: api } = useConsole();
  const issue = useMutation({
    mutationFn: async () => {
      const { data, error } = await api.POST("/admin/tenants/{slug}/clients/{client}/registration-token", { params: { path: { slug: tenant, client: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (data) =>
      onReveal({
        title: "Registration access token",
        description: "Bearer token for the client's management endpoint.",
        values: [
          { label: "Registration access token", value: data.registration_access_token },
          { label: "Registration client URI", value: data.registration_client_uri },
        ],
      }),
  });
  return (
    <>
      <Button disabled={!editable || issue.isPending} onClick={() => issue.mutate()}>
        <KeyRound className="size-4" aria-hidden />
        Issue registration token
      </Button>
      {issue.isError && (
        <p role="alert" className="text-[0.875rem] text-danger">
          {issue.error.message}
        </p>
      )}
    </>
  );
}

function DeleteClient({ tenant, c, onDeleted }: { tenant: string; c: ClientView; onDeleted: () => void }) {
  const { client: api } = useConsole();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await api.DELETE("/admin/tenants/{slug}/clients/{client}", { params: { path: { slug: tenant, client: c.id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["clients", tenant] });
      onDeleted();
    },
  });
  return (
    <section aria-labelledby="delete-client" className="rounded-[calc(var(--radius)+2px)] border border-danger/40 bg-paper px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 id="delete-client" className="text-[1rem] font-semibold text-danger">
            Delete this client
          </h2>
          <p className="text-[0.875rem] text-muted">Revokes its tokens and consents. There is no undo.</p>
        </div>
        <IconButton label="Delete client" onClick={() => setOpen(true)} className="text-danger hover:bg-danger-soft">
          <Trash2 className="size-4" aria-hidden />
        </IconButton>
      </div>
      <Modal open={open} onOpenChange={setOpen} title={`Delete ${c.name}?`} description="Applications using this client will stop working immediately.">
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          {del.isError && (
            <p role="alert" className="text-[0.875rem] text-danger">
              {del.error.message}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="danger" disabled={del.isPending} onClick={() => del.mutate()}>
              {del.isPending ? "Deleting…" : "Delete client"}
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}
