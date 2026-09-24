"use client";

import { useState, type FormEvent } from "react";
import { Authenticate } from "@/components/login/authenticate";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { useErrorText } from "@/components/errors";
import { TermsLabel } from "@/components/terms-label";
import { Alert, Button, Checkbox, PasswordField, Spinner, TextField, Title } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { useFlow, type Post } from "@/lib/flow";
import { usePageParams, WithParams } from "@/lib/params";
import { useTenant } from "@/lib/tenant";
import type { AttributeDef, PublicFlow } from "@/lib/types";

const ACCEPTS = ["authenticate", "password_change", "profile", "terms", "organization", "done"] as const;

export default function Page() {
  return (
    <WithParams>
      <LoginPage />
    </WithParams>
  );
}

function LoginPage() {
  const p = usePageParams();
  if (p.get("preview") === "1") return <PreviewPage tenant={p.tenant} />;
  return <LivePage p={p} />;
}

/**
 * Inside the console's branding editor: the real page on a stand-in flow,
 * so every colour, logo, link and stylesheet change shows at once. Nothing
 * is submitted.
 */
function PreviewPage({ tenant }: { tenant: string | null }) {
  return (
    <AuthShell slug={tenant} preview>
      <PreviewForm tenant={tenant} />
    </AuthShell>
  );
}

function PreviewForm({ tenant }: { tenant: string | null }) {
  const { tenant: info } = useTenant();
  const { t } = useI18n();
  if (!info) return <Spinner label={t("common.loading")} />;
  const flow: PublicFlow = {
    id: "preview",
    stage: "authenticate",
    csrf: "",
    expires_at: "2099-01-01T00:00:00Z",
    client: { client_id: "preview", name: t("login.preview_client"), logo_uri: null, client_uri: null, tos_uri: null, policy_uri: null },
    methods: info.methods,
    login_hint: null,
    ui_locales: [],
    locale: info.locale.default,
    dir: "ltr",
    locales: info.locale.supported,
    pending_scopes: [],
    missing_attributes: [],
    terms_url: info.registration.terms_url,
    privacy_url: info.registration.privacy_url,
    user: null,
    attempts: 0,
    captcha: null,
    mfa: null,
    organizations: [],
    identity_providers: [],
    kerberos: null,
  };
  const post: Post = <T,>() => new Promise<T>(() => {});
  return <Authenticate flow={flow} post={post} reload={() => Promise.resolve()} magic={null} tenant={tenant} preview />;
}

function LivePage({ p }: { p: ReturnType<typeof usePageParams> }) {
  const f = useFlow(p.tenant, p.flow, ACCEPTS);
  const { t } = useI18n();
  const errorText = useErrorText();
  return (
    <AuthShell slug={p.tenant} locale={f.flow?.locale} locales={f.flow?.locales}>
      {f.loading || f.redirected ? (
        <Spinner label={t("common.loading")} />
      ) : f.error || !f.flow ? (
        <Alert tone="error">{errorText(f.error) ?? t("common.expired")}</Alert>
      ) : f.flow.stage === "authenticate" ? (
        <Authenticate flow={f.flow} post={f.post} reload={f.reload} magic={p.get("magic")} tenant={p.tenant} brokerError={p.get("broker_error")} />
      ) : f.flow.stage === "password_change" ? (
        <PasswordChange flow={f.flow} post={f.post} />
      ) : f.flow.stage === "profile" ? (
        <Profile flow={f.flow} post={f.post} />
      ) : f.flow.stage === "terms" ? (
        <Terms flow={f.flow} post={f.post} />
      ) : f.flow.stage === "organization" ? (
        <Organization flow={f.flow} post={f.post} />
      ) : (
        <Spinner label={t("common.loading")} />
      )}
    </AuthShell>
  );
}

function Organization({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [chosen, setChosen] = useState(flow.organizations[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("organization", { org_id: chosen });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("organization.description")}>{t("organization.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      <fieldset className="flex flex-col gap-2">
        <legend className="sr-only">{t("organization.title")}</legend>
        {flow.organizations.map((org) => (
          <label
            key={org.id}
            className="flex min-h-11 cursor-pointer items-center gap-3 rounded-[var(--radius)] border border-line px-3 py-2 hover:bg-paper has-checked:border-accent"
          >
            <input
              type="radio"
              name="organization"
              value={org.id}
              checked={chosen === org.id}
              onChange={() => setChosen(org.id)}
              className="size-4 accent-[var(--accent)]"
            />
            <span className="flex flex-col">
              <span className="text-ink">{org.display_name}</span>
              <span className="text-[0.8125rem] text-muted">{org.slug}</span>
            </span>
          </label>
        ))}
      </fieldset>
      <Button type="submit" busy={busy} disabled={!chosen}>
        {t("organization.continue")}
      </Button>
      <button
        type="button"
        onClick={() => void post("cancel", {}).catch((e: unknown) => setError(errorText(e)))}
        className="self-center text-[0.8125rem] text-muted hover:text-ink hover:underline underline-offset-4"
      >
        {t("common.cancel")}
      </button>
    </form>
  );
}

function PasswordChange({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mismatch = confirm.length > 0 && pw !== confirm;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (mismatch) return;
    setBusy(true);
    setError(null);
    try {
      await post("password-change", { new_password: pw });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("password_change.description")}>{t("password_change.title")}</Title>
      {flow.user && <p className="text-[0.875rem] text-muted">{t("common.signed_in_as", { username: flow.user.username })}</p>}
      {error && <Alert tone="error">{error}</Alert>}
      <PasswordField label={t("password_change.new_password")} value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" autoFocus required />
      <PasswordField
        label={t("password_change.confirm")}
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        autoComplete="new-password"
        error={mismatch ? t("password_change.mismatch") : null}
        required
      />
      <Button type="submit" busy={busy} disabled={mismatch || !pw}>
        {t("common.continue")}
      </Button>
    </form>
  );
}

function Profile({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const defs = [...flow.missing_attributes].sort((a, b) => a.order - b.order);
  const [values, setValues] = useState<Record<string, string | boolean>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("profile", { attributes: encode(defs, values) });
    } catch (err) {
      const fe = err instanceof ApiError ? err.fieldErrors() : {};
      setFieldErrors(fe);
      if (Object.keys(fe).length === 0) setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("profile.description")}>{t("profile.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      {defs.map((d) => (
        <AttributeInput key={d.name} def={d} value={values[d.name]} error={fieldErrors[d.name]} onChange={(v) => setValues((s) => ({ ...s, [d.name]: v }))} />
      ))}
      <Button type="submit" busy={busy}>
        {t("common.continue")}
      </Button>
    </form>
  );
}

function encode(defs: AttributeDef[], values: Record<string, string | boolean>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const d of defs) {
    const v = values[d.name];
    if (v === undefined || v === "") continue;
    if (d.type === "boolean") out[d.name] = Boolean(v);
    else if (d.type === "number") out[d.name] = Number(v);
    else if (d.type === "json") {
      try {
        out[d.name] = JSON.parse(String(v));
      } catch {
        out[d.name] = v;
      }
    } else if (d.multivalued)
      out[d.name] = String(v)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    else out[d.name] = v;
  }
  return out;
}

function AttributeInput({
  def,
  value,
  error,
  onChange,
}: {
  def: AttributeDef;
  value: string | boolean | undefined;
  error?: string;
  onChange: (v: string | boolean) => void;
}) {
  const { t } = useI18n();
  const label = `${def.label ?? def.name}${def.required ? "" : ` (${t("common.optional")})`}`;
  if (def.type === "boolean") {
    return <Checkbox label={label} checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />;
  }
  if (def.type === "enum") {
    return (
      <label className="flex flex-col gap-1.5 text-[0.8125rem] font-medium">
        {label}
        <select
          value={String(value ?? "")}
          onChange={(e) => onChange(e.target.value)}
          required={def.required}
          className="min-h-11 rounded-[var(--radius)] border border-line bg-paper px-3 text-[1rem] font-normal text-ink sm:text-[0.9375rem]"
        >
          <option value="">—</option>
          {def.validation.values.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </label>
    );
  }
  const type =
    def.type === "email" ? "email" : def.type === "url" ? "url" : def.type === "phone" ? "tel" : def.type === "date" ? "date" : def.type === "number" ? "number" : "text";
  return (
    <TextField
      label={label}
      type={type}
      value={String(value ?? "")}
      onChange={(e) => onChange(e.target.value)}
      required={def.required}
      minLength={def.validation.min_length ?? undefined}
      maxLength={def.validation.max_length ?? undefined}
      min={def.validation.min ?? undefined}
      max={def.validation.max ?? undefined}
      pattern={def.validation.pattern ?? undefined}
      hint={def.description}
      error={error}
    />
  );
}

function Terms({ flow, post }: { flow: PublicFlow; post: Post }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("terms", { accepted: true });
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <Title sub={t("terms.description")}>{t("terms.title")}</Title>
      {error && <Alert tone="error">{error}</Alert>}
      <Checkbox checked={accepted} onChange={(e) => setAccepted(e.target.checked)} label={<TermsLabel terms={flow.terms_url} privacy={flow.privacy_url} />} />
      <Button type="submit" busy={busy} disabled={!accepted}>
        {t("terms.accept")}
      </Button>
      <button type="button" onClick={() => void post("cancel", {}).catch((e: unknown) => setError(errorText(e)))} className="self-center text-[0.8125rem] text-muted hover:text-ink hover:underline underline-offset-4">
        {t("common.cancel")}
      </button>
    </form>
  );
}
