"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Field, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { Button, Modal } from "@/components/console/ui";
import { ALL_GRANTS, AUTH_METHODS, CLIENT_TYPES, GRANT_LABELS, STANDARD_SCOPES, isValidClientId, typeDefaults, usesSecret, type AuthMethod, type ClientType, type NewClient, type RevealView } from "@/lib/console/clients";
import { useConsole } from "@/lib/console/session";
import { AudiencePicker, CheckList, ScopePicker } from "./pickers";

const STEPS = ["Type", "Grants", "URIs", "Access"] as const;

/**
 * Four steps: what kind of client, which grants and authentication, where
 * it lives, and what it may ask for. Defaults follow the type, as the API
 * would apply them, so most steps are a glance.
 */
export function ClientWizard({ tenant, open, onOpenChange, onCreated }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void; onCreated: (created: RevealView) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [step, setStep] = useState(0);
  const [type, setType] = useState<ClientType>("spa");
  const [name, setName] = useState("");
  const [clientId, setClientId] = useState("");
  const [grants, setGrants] = useState<string[]>(typeDefaults("spa").grants);
  const [auth, setAuth] = useState<AuthMethod>("none");
  const [pkce, setPkce] = useState(true);
  const [consent, setConsent] = useState(true);
  const [redirects, setRedirects] = useState<string[]>([]);
  const [postLogout, setPostLogout] = useState<string[]>([]);
  const [cors, setCors] = useState<string[]>([]);
  const [scopes, setScopes] = useState<string[] | null>(null);
  const [audiences, setAudiences] = useState<string[]>([]);

  const chooseType = (t: ClientType) => {
    setType(t);
    const d = typeDefaults(t);
    setGrants(d.grants);
    setAuth(d.auth);
    setPkce(d.pkce);
  };
  const needsRedirect = grants.includes("authorization_code");
  const interactive = type !== "machine";

  const create = useMutation({
    mutationFn: async () => {
      // The generated type lists every defaulted field; the API fills what is left out.
      const body: Partial<NewClient> = {
        name: name.trim(),
        client_id: clientId.trim() || null,
        client_type: type,
        allowed_grants: grants,
        token_endpoint_auth_method: auth,
        require_pkce: pkce,
        require_consent: consent,
        redirect_uris: redirects,
        post_logout_redirect_uris: postLogout,
        cors_origins: cors,
        allowed_scopes: scopes,
        allowed_audiences: audiences,
      };
      const { data, error } = await client.POST("/admin/tenants/{slug}/clients", { params: { path: { slug: tenant } }, body: body as NewClient });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (created) => {
      void qc.invalidateQueries({ queryKey: ["clients", tenant] });
      onOpenChange(false);
      onCreated(created);
    },
  });

  const close = (o: boolean) => {
    if (!o) {
      setStep(0);
      create.reset();
    }
    onOpenChange(o);
  };
  const nameOk = name.trim().length > 0;
  const idOk = clientId.trim() === "" || isValidClientId(clientId.trim());
  const stepOk = [nameOk && idOk, grants.length > 0 && !(auth === "none" && grants.includes("client_credentials")), !needsRedirect || redirects.length > 0, true][step];

  return (
    <Modal open={open} onOpenChange={close} title="New client" description={`Step ${step + 1} of ${STEPS.length}: ${STEPS[step]}`} size="lg">
      <ol className="flex gap-1 px-5 pt-3" aria-label="Steps">
        {STEPS.map((s, i) => (
          <li key={s} aria-current={i === step ? "step" : undefined} className={`h-1.5 flex-1 rounded-full ${i <= step ? "bg-accent" : "bg-line"}`}>
            <span className="sr-only">{s}</span>
          </li>
        ))}
      </ol>
      <div className="flex flex-col gap-4 overflow-y-auto px-5 pb-5 pt-4">
        {step === 0 && (
          <>
            <fieldset className="grid gap-2 sm:grid-cols-2">
              <legend className="mb-2 text-[0.8125rem] font-medium text-ink">Kind of client</legend>
              {CLIENT_TYPES.map((t) => (
                <label key={t.value} className={`flex cursor-pointer gap-3 rounded-[var(--radius)] border px-3 py-2.5 ${type === t.value ? "border-accent bg-[color-mix(in_oklab,var(--accent)_8%,transparent)]" : "border-line hover:border-muted/60"}`}>
                  <input type="radio" name="client-type" className="mt-1 accent-[var(--accent)]" checked={type === t.value} onChange={() => chooseType(t.value)} />
                  <span>
                    <span className="block text-[0.9rem] font-medium text-ink">{t.label}</span>
                    <span className="block text-[0.8125rem] text-muted">{t.blurb}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            <Field label="Name">
              {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} placeholder="Customer portal" autoFocus required />}
            </Field>
            <Field label="Client ID" hint="Optional; generated when left empty. Letters, digits, dots, underscores, colons, hyphens." error={idOk ? null : "Must start with a letter or digit and use only [A-Za-z0-9._:-]."}>
              {(id, by) => <TextInput id={id} aria-describedby={by} value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="customer-portal" spellCheck={false} />}
            </Field>
          </>
        )}
        {step === 1 && (
          <>
            <CheckList legend="Grant types" options={ALL_GRANTS.map((g) => ({ value: g, label: GRANT_LABELS[g]! }))} value={grants} onChange={setGrants} />
            <Field label="Client authentication" hint={usesSecret(auth) ? "A secret is generated and shown once when the client is created." : auth === "none" ? "Public clients cannot use client credentials." : "Add the client's JWKS on the detail page."}>
              {(id, by) => (
                <SelectInput id={id} aria-describedby={by} value={auth} onChange={(e) => setAuth(e.target.value as AuthMethod)}>
                  {AUTH_METHODS.map((m) => (
                    <option key={m.value} value={m.value}>
                      {m.label}
                    </option>
                  ))}
                </SelectInput>
              )}
            </Field>
            {interactive && (
              <>
                <Toggle label="Require PKCE" hint="Always on for public clients; recommended for all." checked={pkce} onChange={setPkce} />
                <Toggle label="Ask users for consent" hint="Off for first-party applications." checked={consent} onChange={setConsent} />
              </>
            )}
          </>
        )}
        {step === 2 && (
          <>
            {needsRedirect ? (
              <Field label="Redirect URIs" hint="Exact matches only. Enter adds one.">
                {(id, by) => <TagsInput id={id} describedBy={by} value={redirects} onChange={setRedirects} placeholder="https://app.example.com/callback" />}
              </Field>
            ) : (
              <p className="text-[0.875rem] text-muted">This client does not use browser redirects.</p>
            )}
            {interactive && (
              <Field label="Post-logout redirect URIs" hint="Where the browser may return after signing out.">
                {(id, by) => <TagsInput id={id} describedBy={by} value={postLogout} onChange={setPostLogout} placeholder="https://app.example.com/" />}
              </Field>
            )}
            {(type === "spa" || type === "web") && (
              <Field label="CORS origins" hint="Origins allowed to call the token and userinfo endpoints from a browser.">
                {(id, by) => <TagsInput id={id} describedBy={by} value={cors} onChange={setCors} placeholder="https://app.example.com" />}
              </Field>
            )}
          </>
        )}
        {step === 3 && (
          <>
            <ScopePicker tenant={tenant} value={scopes ?? STANDARD_SCOPES} onChange={setScopes} />
            <AudiencePicker tenant={tenant} value={audiences} onChange={setAudiences} />
          </>
        )}
        {create.isError && (
          <p role="alert" className="text-[0.875rem] text-danger">
            {create.error.message}
          </p>
        )}
        <div className="flex justify-between gap-2 pt-2">
          <Button onClick={() => (step === 0 ? close(false) : setStep(step - 1))}>{step === 0 ? "Cancel" : "Back"}</Button>
          {step < STEPS.length - 1 ? (
            <Button variant="primary" disabled={!stepOk} onClick={() => setStep(step + 1)}>
              Next
            </Button>
          ) : (
            <Button variant="primary" disabled={!stepOk || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? "Creating…" : "Create client"}
            </Button>
          )}
        </div>
      </div>
    </Modal>
  );
}
