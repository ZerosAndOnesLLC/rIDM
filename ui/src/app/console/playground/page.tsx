"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, RotateCw, UserRound } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { CheckList } from "@/components/console/clients/pickers";
import { Field, SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { tenantBase } from "@/lib/api";
import { clientHref, usesSecret, type ClientView } from "@/lib/console/clients";
import { CALLBACK_TYPE, PlaygroundError, decodeJwt, isCallback, pkceChallenge, randomToken, redirectUri, tokenRequest, userinfoRequest, type PlaygroundCallback, type PlaygroundPending, type PlaygroundResult } from "@/lib/console/playground";
import { useConsole } from "@/lib/console/session";
import { useConsoleTenant } from "@/lib/console/tenant";

/**
 * Run a client's flow end to end from the console: authorization code with
 * PKCE through the tenant's real login page, in a popup whose redirect target
 * is this page, or client credentials for machine clients; then look at the
 * tokens, call userinfo and refresh. A run lives in this tab's memory only.
 */
export default function PlaygroundPage() {
  const sp = useSearchParams();
  const tenant = useConsoleTenant();
  const id = sp.get("client");
  const [res, setRes] = useState<PlaygroundResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // The sign-in popup lands here with the authorization response.
  if (sp.get("code") || sp.get("error")) return <Callback />;
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

const noSubscription = () => () => {};

/** In the popup: hand the response to the console tab that opened it, and close. */
function Callback() {
  const sp = useSearchParams();
  // Read on the client only (the static render assumes an opener).
  const orphan = useSyncExternalStore(
    noSubscription,
    () => window.opener === null,
    () => false,
  );
  useEffect(() => {
    const opener = window.opener as Window | null;
    if (!opener) return;
    const message: PlaygroundCallback = {
      type: CALLBACK_TYPE,
      code: sp.get("code"),
      state: sp.get("state"),
      error: sp.get("error"),
      error_description: sp.get("error_description"),
    };
    opener.postMessage(message, window.location.origin);
    window.close();
  }, [sp]);
  if (!orphan) return <Spinner label="Returning to the playground…" />;
  return (
    <>
      <PageHeader title="Playground" />
      <p className="text-[0.9rem] text-muted">This sign-in has no playground to return to. Start the run again from the client&apos;s playground.</p>
    </>
  );
}

function Playground({ tenant, id, res, setRes, error, setError }: { tenant: string; id: string; res: PlaygroundResult | null; setRes: (r: PlaygroundResult | null) => void; error: string | null; setError: (e: string | null) => void }) {
  const { client: api, can } = useConsole();
  const qc = useQueryClient();
  // The run waiting for its popup: in memory, never stored.
  const running = useRef<{ run: PlaygroundPending; popup: Window } | null>(null);
  useEffect(() => {
    const onMessage = (e: MessageEvent) => {
      const current = running.current;
      // Only this origin, only the popup this tab opened.
      if (e.origin !== window.location.origin || !isCallback(e.data) || !current || e.source !== current.popup) return;
      running.current = null;
      const { run } = current;
      const reply = e.data;
      if (reply.error) {
        setError(`${reply.error}: ${reply.error_description ?? "the authorization request was refused."}`);
        return;
      }
      if (!reply.code || reply.state !== run.state) {
        setError("This response does not belong to the run started here.");
        return;
      }
      tokenRequest(run.tenant, run.client_id, run.auth, run.secret, {
        grant_type: "authorization_code",
        code: reply.code,
        redirect_uri: redirectUri(),
        code_verifier: run.verifier,
      })
        .then((tokens) => {
          setRes({ tenant: run.tenant, id: run.id, client_id: run.client_id, auth: run.auth, secret: run.secret, tokens, at: Date.now() });
          setError(null);
        })
        .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)));
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [setRes, setError]);
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
          onStart={(run, popup) => {
            running.current = { run, popup };
            setError(null);
          }}
          onResult={(r) => {
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
          {res ? <Results res={res} onUpdate={setRes} onError={setError} /> : <p className="text-[0.9rem] text-muted">No tokens yet. Start a run on the left.</p>}
        </div>
      </div>
    </>
  );
}

function Runner({ tenant, c, canEdit, onRegistered, onStart, onResult, onError }: { tenant: string; c: ClientView; canEdit: boolean; onRegistered: (c: ClientView) => void; onStart: (run: PlaygroundPending, popup: Window) => void; onResult: (r: PlaygroundResult) => void; onError: (e: string) => void }) {
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
    // Opened now, while the click still counts as the user's: a popup opened
    // after an await is blocked.
    const popup = window.open("about:blank", "ridm-playground", "popup,width=520,height=720");
    if (!popup) {
      onError("The sign-in opens in a popup: allow pop-ups for the console and try again.");
      return;
    }
    const verifier = randomToken(48);
    let challenge: string;
    try {
      challenge = await pkceChallenge(verifier);
    } catch (e) {
      popup.close();
      onError(e instanceof Error ? e.message : String(e));
      return;
    }
    const p: PlaygroundPending = {
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
    onStart(p, popup);
    const q = new URLSearchParams({
      response_type: "code",
      client_id: c.client_id,
      redirect_uri: uri,
      scope: p.scope,
      state: p.state,
      nonce: p.nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    if (resource) q.set("resource", resource);
    if (prompt) q.set("prompt", prompt);
    popup.location.href = `${tenantBase(tenant)}/authorize?${q}`;
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
          <Field label="Client secret" hint="Kept in this tab's memory for the run; never stored.">
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
