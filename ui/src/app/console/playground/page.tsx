"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, RotateCw, UserRound } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { CheckList } from "@/components/console/clients/pickers";
import { Field, SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { tenantBase } from "@/lib/api";
import { clientHref, usesSecret, type ClientView } from "@/lib/console/clients";
import { PlaygroundError, decodeJwt, pending, pkceChallenge, randomToken, redirectUri, result as stored, tokenRequest, userinfoRequest, type PlaygroundResult } from "@/lib/console/playground";
import { useConsole } from "@/lib/console/session";
import { useConsoleTenant } from "@/lib/console/tenant";
import { navigate } from "@/lib/params";

/**
 * Run a client's flow end to end from the console: authorization code with
 * PKCE through the tenant's real login page (the console itself is the
 * redirect target), or client credentials for machine clients; then look at
 * the tokens, call userinfo and refresh.
 */
export default function PlaygroundPage() {
  const sp = useSearchParams();
  const router = useRouter();
  const tenantParam = useConsoleTenant();
  const code = sp.get("code");
  const state = sp.get("state");
  const oauthError = sp.get("error");
  const returning = Boolean(code || oauthError);
  // Coming back from /authorize the URL carries no tenant: the pending record has it.
  const [pend] = useState(() => (returning && typeof window !== "undefined" ? pending.load() : null));
  const tenant = tenantParam && !returning ? tenantParam : (pend?.tenant ?? tenantParam);
  const id = sp.get("client") ?? pend?.id ?? null;

  const [res, setRes] = useState<PlaygroundResult | null>(() => (typeof window === "undefined" ? null : stored.load()));
  const [error, setError] = useState<string | null>(null);
  const exchanged = useRef(false);

  useEffect(() => {
    if (!returning || exchanged.current) return;
    exchanged.current = true;
    const p = pend;
    pending.clear();
    const finish = (r: PlaygroundResult | null, err: string | null) => {
      if (r) {
        stored.save(r);
        setRes(r);
      }
      setError(err);
      if (p) router.replace(`/console/playground/?tenant=${encodeURIComponent(p.tenant)}&client=${encodeURIComponent(p.id)}`);
    };
    if (oauthError) {
      finish(null, `${oauthError}: ${sp.get("error_description") ?? "the authorization request was refused."}`);
      return;
    }
    if (!p || p.state !== state) {
      finish(null, "This response does not belong to a run started in this tab.");
      return;
    }
    tokenRequest(p.tenant, p.client_id, p.auth, p.secret, {
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: redirectUri(),
      code_verifier: p.verifier,
    })
      .then((tokens) => finish({ tenant: p.tenant, id: p.id, client_id: p.client_id, auth: p.auth, secret: p.secret, tokens, at: Date.now() }, null))
      .catch((e: unknown) => finish(null, e instanceof Error ? e.message : String(e)));
  }, [returning, oauthError, code, state, sp, router, pend]);

  if (!tenant || !id) {
    return (
      <>
        <PageHeader title="Playground" />
        <p className="text-[0.9rem] text-muted">Open the playground from a client&apos;s page.</p>
      </>
    );
  }
  return <Playground tenant={tenant} id={id} res={res && res.id === id ? res : null} setRes={setRes} error={error} setError={setError} />;
}

function Playground({ tenant, id, res, setRes, error, setError }: { tenant: string; id: string; res: PlaygroundResult | null; setRes: (r: PlaygroundResult | null) => void; error: string | null; setError: (e: string | null) => void }) {
  const { client: api, can } = useConsole();
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["client", tenant, id],
    queryFn: async () => {
      const { data, error } = await api.GET("/admin/tenants/{slug}/clients/{client}", { params: { path: { slug: tenant, client: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  if (query.isError) {
    return (
      <p role="alert" className="text-[0.9rem] text-danger">
        {query.error.message}
      </p>
    );
  }
  if (!query.data) return <Spinner label="Loading client…" />;
  const c = query.data;
  return (
    <>
      <PageHeader
        title="Playground"
        sub={
          <span className="inline-flex flex-wrap items-center gap-2">
            {c.name} <code className="font-mono text-[0.8125rem]">{c.client_id}</code>
            <Link href={clientHref(tenant, c.id)} className="text-link underline underline-offset-4">
              Client settings
            </Link>
          </span>
        }
      />
      <div className="grid gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
        <Runner
          tenant={tenant}
          c={c}
          canEdit={can("ridm:clients:write")}
          onRegistered={(updated) => qc.setQueryData(["client", tenant, id], updated)}
          onResult={(r) => {
            stored.save(r);
            setRes(r);
            setError(null);
          }}
          onError={setError}
        />
        <div className="flex min-w-0 flex-col gap-4">
          {error && (
            <p role="alert" className="rounded-[var(--radius)] bg-danger-soft px-4 py-3 text-[0.875rem] text-danger">
              {error}
            </p>
          )}
          {res ? <Results res={res} onUpdate={(r) => { stored.save(r); setRes(r); }} onError={setError} /> : <p className="text-[0.9rem] text-muted">No tokens yet. Start a run on the left.</p>}
        </div>
      </div>
    </>
  );
}

function Runner({ tenant, c, canEdit, onRegistered, onResult, onError }: { tenant: string; c: ClientView; canEdit: boolean; onRegistered: (c: ClientView) => void; onResult: (r: PlaygroundResult) => void; onError: (e: string) => void }) {
  const { client: api } = useConsole();
  const interactive = c.allowed_grants.includes("authorization_code");
  const machine = c.allowed_grants.includes("client_credentials");
  const [scopes, setScopes] = useState<string[]>(() => c.allowed_scopes.filter((s) => s !== "offline_access"));
  const [resource, setResource] = useState<string>("");
  const [prompt, setPrompt] = useState<string>("");
  const [secret, setSecret] = useState("");
  const uri = redirectUri();
  const registered = c.redirect_uris.includes(uri);
  const needsSecret = usesSecret(c.token_endpoint_auth_method);

  const register = useMutation({
    mutationFn: async () => {
      const { data, error } = await api.PATCH("/admin/tenants/{slug}/clients/{client}", { params: { path: { slug: tenant, client: c.id } }, body: { redirect_uris: [...c.redirect_uris, uri] } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: onRegistered,
  });

  const start = async () => {
    if (needsSecret && !secret.trim()) {
      onError("Paste the client secret to run a confidential client.");
      return;
    }
    const verifier = randomToken(48);
    const p = {
      tenant,
      id: c.id,
      client_id: c.client_id,
      auth: c.token_endpoint_auth_method,
      secret: needsSecret ? secret : null,
      verifier,
      state: randomToken(16),
      nonce: randomToken(16),
      scope: scopes.join(" "),
      resource: resource || null,
    };
    pending.save(p);
    const q = new URLSearchParams({
      response_type: "code",
      client_id: c.client_id,
      redirect_uri: uri,
      scope: p.scope,
      state: p.state,
      nonce: p.nonce,
      code_challenge: await pkceChallenge(verifier),
      code_challenge_method: "S256",
    });
    if (resource) q.set("resource", resource);
    if (prompt) q.set("prompt", prompt);
    navigate(`${tenantBase(tenant)}/authorize?${q}`);
  };

  const credentials = useMutation({
    mutationFn: () => tokenRequest(tenant, c.client_id, c.token_endpoint_auth_method, secret || null, { grant_type: "client_credentials", scope: scopes.join(" "), ...(resource ? { resource } : {}) }),
    onSuccess: (tokens) => onResult({ tenant, id: c.id, client_id: c.client_id, auth: c.token_endpoint_auth_method, secret: secret || null, tokens, at: Date.now() }),
    onError: (e) => onError(e instanceof Error ? e.message : String(e)),
  });

  return (
    <Card title="Run">
      <div className="flex flex-col gap-4">
        {!interactive && !machine && <p className="text-[0.875rem] text-muted">This client uses neither the authorization code nor the client credentials grant; the device flow playground arrives with Phase 8.</p>}
        {interactive && !registered && (
          <div className="rounded-[var(--radius)] bg-ground px-3.5 py-3 text-[0.8125rem] text-ink">
            <p>
              The playground returns to <code className="font-mono">{uri}</code>, which is not one of this client&apos;s redirect URIs.
            </p>
            {canEdit ? (
              <Button className="mt-2" disabled={register.isPending} onClick={() => register.mutate()}>
                Add it to the redirect URIs
              </Button>
            ) : (
              <p className="mt-1 text-muted">Ask an administrator to add it.</p>
            )}
            {register.isError && (
              <p role="alert" className="mt-1 text-danger">
                {register.error.message}
              </p>
            )}
          </div>
        )}
        <CheckList legend="Scopes" options={c.allowed_scopes.map((s) => ({ value: s, label: s }))} value={scopes} onChange={setScopes} />
        {c.allowed_audiences.length > 0 && (
          <Field label="Audience (resource)" hint="Empty asks for every allowed audience.">
            {(fid, by) => (
              <SelectInput id={fid} aria-describedby={by} value={resource} onChange={(e) => setResource(e.target.value)}>
                <option value="">Default</option>
                {c.allowed_audiences.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </SelectInput>
            )}
          </Field>
        )}
        {interactive && (
          <Field label="Prompt">
            {(fid) => (
              <SelectInput id={fid} value={prompt} onChange={(e) => setPrompt(e.target.value)}>
                <option value="">Default</option>
                <option value="login">login (always ask for credentials)</option>
                <option value="consent">consent (always ask for consent)</option>
                <option value="select_account">select_account</option>
                <option value="none">none (fail unless already signed in)</option>
              </SelectInput>
            )}
          </Field>
        )}
        {needsSecret && (
          <Field label="Client secret" hint="Kept in this tab only until the run completes.">
            {(fid, by) => <TextInput id={fid} aria-describedby={by} type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />}
          </Field>
        )}
        {c.token_endpoint_auth_method === "private_key_jwt" && <p className="text-[0.8125rem] text-muted">The playground cannot sign private_key_jwt assertions.</p>}
        <div className="flex flex-wrap gap-2">
          {interactive && (
            <Button variant="primary" disabled={!registered || scopes.length === 0 || c.token_endpoint_auth_method === "private_key_jwt"} onClick={() => void start()}>
              <Play className="size-4" aria-hidden />
              Sign in as a user
            </Button>
          )}
          {machine && (
            <Button variant={interactive ? "secondary" : "primary"} disabled={credentials.isPending || c.token_endpoint_auth_method === "private_key_jwt"} onClick={() => credentials.mutate()}>
              <Play className="size-4" aria-hidden />
              Get a token (client credentials)
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

function Results({ res, onUpdate, onError }: { res: PlaygroundResult; onUpdate: (r: PlaygroundResult) => void; onError: (e: string) => void }) {
  const at = decodeJwt(res.tokens.access_token);
  const idt = res.tokens.id_token ? decodeJwt(res.tokens.id_token) : null;
  const userinfo = useMutation({
    mutationFn: () => userinfoRequest(res.tenant, res.tokens.access_token),
    onSuccess: (data) => onUpdate({ ...res, userinfo: data }),
    onError: (e) => onError(e instanceof PlaygroundError ? e.message : String(e)),
  });
  const refresh = useMutation({
    mutationFn: () => tokenRequest(res.tenant, res.client_id, res.auth, res.secret, { grant_type: "refresh_token", refresh_token: res.tokens.refresh_token! }),
    onSuccess: (tokens) => onUpdate({ ...res, tokens, userinfo: undefined, at: Date.now() }),
    onError: (e) => onError(e instanceof PlaygroundError ? e.message : String(e)),
  });
  return (
    <>
      <Card
        title="Token response"
        actions={
          <span className="flex flex-wrap gap-2">
            <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={userinfo.isPending} onClick={() => userinfo.mutate()}>
              <UserRound className="size-3.5" aria-hidden />
              Call userinfo
            </Button>
            {res.tokens.refresh_token && (
              <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={refresh.isPending} onClick={() => refresh.mutate()}>
                <RotateCw className="size-3.5" aria-hidden />
                Refresh
              </Button>
            )}
          </span>
        }
      >
        <div className="mb-3 flex flex-wrap gap-2">
          {res.tokens.expires_in !== undefined && <Badge>expires in {res.tokens.expires_in}s</Badge>}
          {res.tokens.scope && <Badge>{res.tokens.scope}</Badge>}
          {res.tokens.refresh_token && <Badge tone="accent">refresh token</Badge>}
          {res.tokens.id_token && <Badge tone="accent">ID token</Badge>}
        </div>
        <Json value={res.tokens} label="Token response" />
      </Card>
      {at ? (
        <Card title="Access token">
          <p className="mb-2 text-[0.8125rem] text-muted">Header</p>
          <Json value={at.header} label="Access token header" />
          <p className="mb-2 mt-3 text-[0.8125rem] text-muted">Claims</p>
          <Json value={at.claims} label="Access token claims" />
        </Card>
      ) : (
        <Card title="Access token">
          <p className="text-[0.875rem] text-muted">Opaque token; inspect it through introspection.</p>
        </Card>
      )}
      {idt && (
        <Card title="ID token claims">
          <Json value={idt.claims} label="ID token claims" />
        </Card>
      )}
      {res.userinfo !== undefined && (
        <Card title="userinfo">
          <Json value={res.userinfo} label="userinfo response" />
        </Card>
      )}
    </>
  );
}

function Json({ value, label = "JSON" }: { value: unknown; label?: string }) {
  // Scrollable, so it must be reachable from the keyboard.
  return (
    <pre tabIndex={0} aria-label={label} className="max-h-96 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-[0.8125rem] text-ink">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}
