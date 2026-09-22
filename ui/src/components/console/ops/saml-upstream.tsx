"use client";

import { useMutation } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { Field, Section, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { Button, Card } from "@/components/console/ui";
import type { IdentityProvider, SamlUpstream, SamlUpstreamSettings } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";
import { CopyButton } from "../clients/reveal";
import { Certificates } from "./saml";

/** The settings of a stored SAML provider, without its read-only refresh status. */
function settingsOf(s: SamlUpstream): SamlUpstreamSettings {
  const settings: Partial<SamlUpstream> = { ...s };
  delete settings.metadata_refreshed_at;
  delete settings.metadata_error;
  return settings as SamlUpstreamSettings;
}

function Url({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[0.8125rem] font-medium text-ink">{label}</span>
      <div className="flex flex-wrap items-center gap-2">
        <code className="min-w-0 break-all rounded-[var(--radius)] bg-ground px-2 py-1 font-mono text-[0.8125rem] text-ink">{value}</code>
        <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} />
      </div>
    </div>
  );
}

/** What the upstream IdP is configured with: rIDM's SP entity ID and URLs. */
export function SamlSpDetails({ provider }: { provider: IdentityProvider }) {
  const sp = provider.saml_sp;
  if (!sp) return null;
  return (
    <Card title="Service provider details">
      <p className="text-[0.875rem] text-muted">
        Give the identity provider rIDM&rsquo;s metadata, which names everything below and the certificate requests are signed with, or enter these by hand.{" "}
        <a href={sp.metadata_url} target="_blank" rel="noreferrer" className="text-accent underline-offset-4 hover:underline">
          Open the metadata
        </a>
        .
      </p>
      <div className="mt-3 flex flex-col gap-3">
        <Url label="Entity ID" value={sp.entity_id} />
        <Url label="Assertion consumer service" value={sp.acs_url} />
        <Url label="Single logout service" value={sp.slo_url} />
      </div>
    </Card>
  );
}

/** The SAML settings of a provider, auto-saved as a whole on every change. */
export function SamlUpstreamSection({
  tenant,
  provider,
  editable,
  onChange,
  onRefreshed,
}: {
  tenant: string;
  provider: IdentityProvider;
  editable: boolean;
  onChange: (s: SamlUpstreamSettings) => void;
  onRefreshed: (p: IdentityProvider) => void;
}) {
  const { client } = useConsole();
  const saml = provider.saml;
  const refresh = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/identity-providers/{idp}/saml/refresh", { params: { path: { slug: tenant, idp: provider.id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: onRefreshed,
  });
  if (!saml) return null;
  const s = settingsOf(saml);
  const set = (patch: Partial<SamlUpstreamSettings>) => onChange({ ...s, ...patch });
  return (
    <>
      <Section id="idp-saml" title="Identity provider" description="Where rIDM sends the browser, and the certificates the assertions must be signed with.">
        <Field label="Entity ID" hint="The Issuer of its responses." wide>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.entity_id} disabled={!editable} spellCheck={false} onChange={(e) => set({ entity_id: e.target.value })} />}
        </Field>
        <Field label="Single sign-on URL" wide>
          {(fid) => <TextInput id={fid} type="url" value={s.sso_url} disabled={!editable} spellCheck={false} onChange={(e) => set({ sso_url: e.target.value })} />}
        </Field>
        <Field label="Sign-on binding">
          {(fid) => (
            <SelectInput id={fid} value={s.sso_binding} disabled={!editable} onChange={(e) => set({ sso_binding: e.target.value as SamlUpstreamSettings["sso_binding"] })}>
              <option value="redirect">HTTP-Redirect</option>
              <option value="post">HTTP-POST</option>
            </SelectInput>
          )}
        </Field>
        <Field label="NameID format" hint="Asked for in the request; persistent is the one made for linking accounts.">
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={s.name_id_format ?? ""} disabled={!editable} onChange={(e) => set({ name_id_format: (e.target.value || null) as SamlUpstreamSettings["name_id_format"] })}>
              <option value="">Not asked</option>
              <option value="persistent">Persistent</option>
              <option value="email">Email address</option>
              <option value="transient">Transient (needs a subject attribute)</option>
              <option value="unspecified">Unspecified</option>
            </SelectInput>
          )}
        </Field>
        <Field label="Single logout URL" hint="Leave empty to keep sign-out local to rIDM." wide>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} type="url" value={s.slo_url ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ slo_url: e.target.value || null })} />}
        </Field>
        <Field label="Logout binding">
          {(fid) => (
            <SelectInput id={fid} value={s.slo_binding} disabled={!editable} onChange={(e) => set({ slo_binding: e.target.value as SamlUpstreamSettings["slo_binding"] })}>
              <option value="redirect">HTTP-Redirect</option>
              <option value="post">HTTP-POST</option>
            </SelectInput>
          )}
        </Field>
        <Certificates
          value={s.signing_certificates}
          disabled={!editable}
          onChange={(v) => set({ signing_certificates: v })}
          label="Signing certificates"
          hint="Responses and assertions must be signed with one of these; list two during the identity provider's key rollover. A metadata URL keeps them current."
          empty="None: nothing can be accepted until one is added."
        />
      </Section>
      <Section id="idp-saml-security" title="Signatures and encryption">
        <div className="sm:col-span-2 flex flex-col gap-1">
          <Toggle label="Sign requests" hint="AuthnRequests carry the tenant's SAML signature; logout messages are always signed." checked={s.sign_requests} disabled={!editable} onChange={(v) => set({ sign_requests: v })} />
          <Toggle label="Require signed assertions" hint="A signed response around an unsigned assertion is refused." checked={s.want_assertions_signed} disabled={!editable} onChange={(v) => set({ want_assertions_signed: v })} />
          <Toggle label="Require encrypted assertions" hint="The identity provider encrypts to the certificate in rIDM's metadata." checked={s.require_encrypted_assertions} disabled={!editable} onChange={(v) => set({ require_encrypted_assertions: v })} />
          <Toggle label="Force authentication" hint="Ask the identity provider to sign the user in again every time." checked={s.force_authn} disabled={!editable} onChange={(v) => set({ force_authn: v })} />
        </div>
        <Field label="Authentication context classes" hint="Asked for with Comparison exact, e.g. https://refeds.org/profile/mfa. None asks for nothing." wide>
          {(fid, by) => <TagsInput id={fid} describedBy={by} value={s.authn_context_class_refs} onChange={(v) => set({ authn_context_class_refs: v })} placeholder="https://refeds.org/profile/mfa" />}
        </Field>
      </Section>
      <Section id="idp-saml-unsolicited" title="IdP-initiated sign-in" description="Responses rIDM did not ask for. Off by default: a forged one could sign a victim in to the attacker's account.">
        <div className="sm:col-span-2">
          <Toggle label="Accept unsolicited responses" checked={s.allow_unsolicited} disabled={!editable} onChange={(v) => set({ allow_unsolicited: v })} />
        </div>
        <Field label="Land on client" hint="Its initiate_login_uri receives the browser; the account console when empty." wide>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={s.unsolicited_client_id ?? ""} disabled={!editable || !s.allow_unsolicited} spellCheck={false} placeholder="my-app" onChange={(e) => set({ unsolicited_client_id: e.target.value || null })} />}
        </Field>
      </Section>
      <Section id="idp-saml-metadata" title="Metadata" description="With a metadata URL, rIDM re-reads it daily and takes the endpoints and certificates from it, so the identity provider's key rollover needs nobody here.">
        <Field label="Metadata URL" wide>
          {(fid) => <TextInput id={fid} type="url" value={s.metadata_url ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => set({ metadata_url: e.target.value || null })} />}
        </Field>
        <div className="sm:col-span-2 flex flex-col gap-2">
          <p className="text-[0.8125rem] text-muted" aria-live="polite">
            {saml.metadata_error
              ? `Last refresh failed: ${saml.metadata_error}`
              : saml.metadata_refreshed_at
                ? `Last read ${new Date(saml.metadata_refreshed_at).toLocaleString()}.`
                : s.metadata_url
                  ? "Not read yet."
                  : "No metadata URL: the settings above stay as they are."}
          </p>
          {editable && saml.metadata_url && (
            <div>
              <Button disabled={refresh.isPending} onClick={() => refresh.mutate()}>
                <RefreshCw className="size-4" aria-hidden />
                {refresh.isPending ? "Refreshing…" : "Refresh now"}
              </Button>
            </div>
          )}
          <ErrorLine error={refresh.error} />
        </div>
      </Section>
    </>
  );
}
