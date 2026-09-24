"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Field, NumberInput, SelectInput, TextArea, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useDebounced } from "@/lib/console/hooks";
import { href, type LogEntry } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

const TABS = ["email", "sms", "templates", "log"] as const;
type Tab = (typeof TABS)[number];
const LABELS: Record<Tab, string> = { email: "Email", sms: "SMS", templates: "Templates", log: "Delivery log" };

export function MessagingPage({ tenant, tab }: { tenant: string; tab: string | null }) {
  const current: Tab = (TABS as readonly string[]).includes(tab ?? "") ? (tab as Tab) : "email";
  return (
    <>
      <PageHeader title="Messaging" sub="How this tenant sends email and SMS, the templates it uses, and what went out." />
      <nav aria-label="Messaging sections" className="mb-5 flex flex-wrap gap-1 border-b border-line">
        {TABS.map((t) => (
          <Link key={t} href={href("messaging", tenant, { tab: t })} aria-current={t === current ? "page" : undefined} className={`-mb-px border-b-2 px-3 py-2 text-[0.875rem] ${t === current ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}>
            {LABELS[t]}
          </Link>
        ))}
      </nav>
      {current === "email" && <EmailTab tenant={tenant} />}
      {current === "sms" && <SmsTab tenant={tenant} />}
      {current === "templates" && <TemplatesTab tenant={tenant} />}
      {current === "log" && <LogTab tenant={tenant} />}
    </>
  );
}

function TestSend({ tenant, channel }: { tenant: string; channel: "email" | "sms" }) {
  const { client } = useConsole();
  const [to, setTo] = useState("");
  const send = useMutation({
    mutationFn: async () => {
      const r = channel === "email" ? await client.POST("/admin/tenants/{slug}/messaging/email/test", { params: { path: { slug: tenant } }, body: { to: to.trim() } }) : await client.POST("/admin/tenants/{slug}/messaging/sms/test", { params: { path: { slug: tenant } }, body: { to: to.trim() } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
      return r.data;
    },
  });
  return (
    <form
      className="flex flex-wrap items-end gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (to.trim()) send.mutate();
      }}
    >
      <Field label={channel === "email" ? "Send a test email to" : "Send a test SMS to"}>
        {(id) => <TextInput id={id} type={channel === "email" ? "email" : "tel"} value={to} onChange={(e) => setTo(e.target.value)} placeholder={channel === "email" ? "you@example.com" : "+15550100"} className="min-w-[16rem]" />}
      </Field>
      <Button type="submit" disabled={!to.trim() || send.isPending}>
        {send.isPending ? "Sending…" : "Send test"}
      </Button>
      {send.data && (
        <span role="status" className="text-[0.8125rem] text-ok">
          Sent to {send.data.to} through {send.data.sender}.
        </span>
      )}
      <ErrorLine error={send.error} />
    </form>
  );
}

function EmailTab({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const editable = can("ridm:messaging:write");
  const settings = useQuery({
    queryKey: ["messaging", tenant, "email"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/messaging/email", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [kind, setKind] = useState<"smtp" | "http">("smtp");
  const [host, setHost] = useState("");
  const [port, setPort] = useState<number | null>(587);
  const [security, setSecurity] = useState("starttls");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState("");
  const [url, setUrl] = useState("");
  const [authHeader, setAuthHeader] = useState("");
  const [seeded, setSeeded] = useState(false);
  const view = settings.data;
  if (view !== undefined && !seeded) {
    setSeeded(true);
    if (view && "type" in view && view.type === "smtp") {
      setKind("smtp");
      setHost(view.host);
      setPort(view.port);
      setSecurity(view.security);
      setUsername(view.username ?? "");
      setFrom(view.from);
    } else if (view && "type" in view && view.type === "http") {
      setKind("http");
      setUrl(view.url);
      setFrom(view.from);
    }
  }
  const save = useMutation({
    mutationFn: async () => {
      const body = kind === "smtp" ? { type: "smtp" as const, host: host.trim(), port: port ?? 587, security, username: username.trim() || null, password: password || null, from: from.trim() } : { type: "http" as const, url: url.trim(), auth_header: authHeader || null, from: from.trim() };
      const { error } = await client.PUT("/admin/tenants/{slug}/messaging/email", { params: { path: { slug: tenant } }, body: body as never });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setPassword("");
      setAuthHeader("");
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "email"] });
    },
  });
  const remove = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/messaging/email", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setSeeded(false);
      setHost("");
      setUrl("");
      setFrom("");
      setUsername("");
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "email"] });
    },
  });
  if (settings.isPending) return <Spinner label="Loading…" />;
  if (settings.isError) return <ErrorLine error={settings.error} />;
  const source = view?.source;
  const secretSet = view && "type" in view ? (view.type === "smtp" ? view.password_set : view.auth_header_set) : false;
  return (
    <div className="flex flex-col gap-4">
      <Card title="Provider" actions={source === "tenant" ? <Badge tone="ok">Tenant settings</Badge> : source === "server_default" ? <Badge>Server default</Badge> : <Badge tone="danger">No email</Badge>}>
        <p className="mb-4 text-[0.8125rem] text-muted">Without tenant settings the server&apos;s SMTP defaults apply, if any. Secrets are stored encrypted and never shown again.</p>
        <form
          className="grid gap-4 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="Delivery">
            {(id) => (
              <SelectInput id={id} value={kind} disabled={!editable} onChange={(e) => setKind(e.target.value as "smtp" | "http")}>
                <option value="smtp">SMTP</option>
                <option value="http">HTTP webhook (JSON)</option>
              </SelectInput>
            )}
          </Field>
          <Field label="From address">{(id) => <TextInput id={id} value={from} disabled={!editable} onChange={(e) => setFrom(e.target.value)} placeholder="Acme <no-reply@acme.example>" required />}</Field>
          {kind === "smtp" ? (
            <>
              <Field label="Host">{(id) => <TextInput id={id} value={host} disabled={!editable} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" required spellCheck={false} />}</Field>
              <Field label="Port">{(id) => <NumberInput id={id} value={port} min={1} max={65535} onValue={setPort} />}</Field>
              <Field label="Security">
                {(id) => (
                  <SelectInput id={id} value={security} disabled={!editable} onChange={(e) => setSecurity(e.target.value)}>
                    <option value="starttls">STARTTLS</option>
                    <option value="tls">TLS</option>
                    <option value="none">None</option>
                  </SelectInput>
                )}
              </Field>
              <Field label="Username">{(id) => <TextInput id={id} value={username} disabled={!editable} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />}</Field>
              <Field label="Password" hint={secretSet ? "A password is stored; leave empty to keep it." : undefined}>
                {(id, by) => <TextInput id={id} aria-describedby={by} type="password" autoComplete="new-password" value={password} disabled={!editable} onChange={(e) => setPassword(e.target.value)} />}
              </Field>
            </>
          ) : (
            <>
              <Field label="URL">{(id) => <TextInput id={id} type="url" value={url} disabled={!editable} onChange={(e) => setUrl(e.target.value)} placeholder="https://mail.example.com/send" required spellCheck={false} />}</Field>
              <Field label="Authorization header" hint={secretSet ? "A header is stored; leave empty to keep it." : "Sent as-is, e.g. Bearer …"}>
                {(id, by) => <TextInput id={id} aria-describedby={by} type="password" autoComplete="off" value={authHeader} disabled={!editable} onChange={(e) => setAuthHeader(e.target.value)} />}
              </Field>
            </>
          )}
          {editable && (
            <div className="flex gap-2 sm:col-span-2">
              <Button type="submit" variant="primary" disabled={save.isPending}>
                {save.isPending ? "Saving…" : "Save email settings"}
              </Button>
              {source === "tenant" && (
                <Button variant="danger" disabled={remove.isPending} onClick={() => remove.mutate()}>
                  Remove tenant settings
                </Button>
              )}
            </div>
          )}
          {save.isSuccess && (
            <p role="status" className="text-[0.8125rem] text-ok sm:col-span-2">
              Saved.
            </p>
          )}
          <div className="sm:col-span-2">
            <ErrorLine error={save.error ?? remove.error} />
          </div>
        </form>
      </Card>
      {source !== "none" && (
        <Card title="Test">
          <TestSend tenant={tenant} channel="email" />
        </Card>
      )}
    </div>
  );
}

function SmsTab({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const editable = can("ridm:messaging:write");
  const settings = useQuery({
    queryKey: ["messaging", tenant, "sms"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/messaging/sms", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [url, setUrl] = useState("");
  const [from, setFrom] = useState("");
  const [authHeader, setAuthHeader] = useState("");
  const [seeded, setSeeded] = useState(false);
  if (settings.data && !seeded) {
    setSeeded(true);
    setUrl(settings.data.url ?? "");
    setFrom(settings.data.from ?? "");
  }
  const save = useMutation({
    mutationFn: async () => {
      const { error } = await client.PUT("/admin/tenants/{slug}/messaging/sms", { params: { path: { slug: tenant } }, body: { url: url.trim(), from: from.trim() || null, auth_header: authHeader || null } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setAuthHeader("");
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "sms"] });
    },
  });
  const remove = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/messaging/sms", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setUrl("");
      setFrom("");
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "sms"] });
    },
  });
  if (settings.isPending) return <Spinner label="Loading…" />;
  if (settings.isError) return <ErrorLine error={settings.error} />;
  return (
    <div className="flex flex-col gap-4">
      <Card title="Gateway" actions={settings.data.configured ? <Badge tone="ok">Configured</Badge> : <Badge>Not configured</Badge>}>
        <p className="mb-4 text-[0.8125rem] text-muted">Any HTTP gateway receiving JSON {"{to, from, text}"}. SMS codes and notices need it.</p>
        <form
          className="grid gap-4 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="URL">{(id) => <TextInput id={id} type="url" value={url} disabled={!editable} onChange={(e) => setUrl(e.target.value)} placeholder="https://sms.example.com/send" required spellCheck={false} />}</Field>
          <Field label="Sender">{(id) => <TextInput id={id} value={from} disabled={!editable} onChange={(e) => setFrom(e.target.value)} placeholder="Acme" />}</Field>
          <Field label="Authorization header" hint={settings.data.auth_header_set ? "A header is stored; leave empty to keep it." : "Sent as-is, e.g. Bearer …"} wide>
            {(id, by) => <TextInput id={id} aria-describedby={by} type="password" autoComplete="off" value={authHeader} disabled={!editable} onChange={(e) => setAuthHeader(e.target.value)} />}
          </Field>
          {editable && (
            <div className="flex gap-2 sm:col-span-2">
              <Button type="submit" variant="primary" disabled={!url.trim() || save.isPending}>
                {save.isPending ? "Saving…" : "Save SMS settings"}
              </Button>
              {settings.data.configured && (
                <Button variant="danger" disabled={remove.isPending} onClick={() => remove.mutate()}>
                  Remove
                </Button>
              )}
            </div>
          )}
          {save.isSuccess && (
            <p role="status" className="text-[0.8125rem] text-ok sm:col-span-2">
              Saved.
            </p>
          )}
          <div className="sm:col-span-2">
            <ErrorLine error={save.error ?? remove.error} />
          </div>
        </form>
      </Card>
      {settings.data.configured && (
        <Card title="Test">
          <TestSend tenant={tenant} channel="sms" />
        </Card>
      )}
    </div>
  );
}

function TemplatesTab({ tenant }: { tenant: string }) {
  const { client } = useConsole();
  const catalogue = useQuery({
    queryKey: ["messaging", tenant, "templates"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/messaging/templates", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [channel, setChannel] = useState<"email" | "sms">("email");
  const [event, setEvent] = useState("");
  const [locale, setLocale] = useState("en");
  if (catalogue.isPending) return <Spinner label="Loading…" />;
  if (catalogue.isError) return <ErrorLine error={catalogue.error} />;
  const ev = event || catalogue.data.events[0] || "";
  const overridden = new Set(catalogue.data.overrides.map((o) => `${o.channel}/${o.event}/${o.locale}`));
  return (
    <div className="grid gap-4 lg:grid-cols-[16rem_minmax(0,1fr)]">
      <Card title="Template">
        <div className="flex flex-col gap-3">
          <Field label="Channel">
            {(id) => (
              <SelectInput id={id} value={channel} onChange={(e) => setChannel(e.target.value as "email" | "sms")}>
                {catalogue.data.channels.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </SelectInput>
            )}
          </Field>
          <Field label="Event">
            {(id) => (
              <SelectInput id={id} value={ev} onChange={(e) => setEvent(e.target.value)}>
                {catalogue.data.events.map((e) => (
                  <option key={e} value={e}>
                    {e}
                    {overridden.has(`${channel}/${e}/${locale}`) ? " •" : ""}
                  </option>
                ))}
              </SelectInput>
            )}
          </Field>
          <Field label="Locale" hint="Falls back to the language, then to the built-in English.">
            {(id, by) => <TextInput id={id} aria-describedby={by} value={locale} onChange={(e) => setLocale(e.target.value.trim() || "en")} spellCheck={false} />}
          </Field>
          <p className="text-[0.75rem] text-muted">• = this tenant overrides the built-in template.</p>
        </div>
      </Card>
      {ev && <TemplateEditor key={`${channel}/${ev}/${locale}`} tenant={tenant} channel={channel} event={ev} locale={locale} />}
    </div>
  );
}

function TemplateEditor({ tenant, channel, event, locale }: { tenant: string; channel: "email" | "sms"; event: string; locale: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const editable = can("ridm:messaging:write");
  const path = { slug: tenant, channel, event, locale };
  const tpl = useQuery({
    queryKey: ["messaging", tenant, "template", channel, event, locale],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/messaging/templates/{channel}/{event}/{locale}", { params: { path } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [subject, setSubject] = useState("");
  const [text, setText] = useState("");
  const [html, setHtml] = useState("");
  const [seeded, setSeeded] = useState(false);
  const [showHtml, setShowHtml] = useState(false);
  if (tpl.data && !seeded) {
    setSeeded(true);
    setSubject(tpl.data.subject ?? "");
    setText(tpl.data.body_text);
    setHtml(tpl.data.body_html ?? "");
  }
  const draft = useDebounced(JSON.stringify({ subject, text, html }), 500);
  const preview = useQuery({
    queryKey: ["messaging", tenant, "preview", channel, event, locale, draft],
    enabled: seeded,
    queryFn: async () => {
      const d = JSON.parse(draft) as { subject: string; text: string; html: string };
      const { data, error } = await client.POST("/admin/tenants/{slug}/messaging/templates/preview", {
        params: { path: { slug: tenant } },
        body: { channel, event, locale, draft: { subject: d.subject || null, body_text: d.text, body_html: d.html || null }, vars: null },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const save = useMutation({
    mutationFn: async () => {
      const { error } = await client.PUT("/admin/tenants/{slug}/messaging/templates/{channel}/{event}/{locale}", { params: { path }, body: { subject: subject || null, body_text: text, body_html: html || null } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "templates"] });
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "template", channel, event, locale] });
    },
  });
  const reset = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/messaging/templates/{channel}/{event}/{locale}", { params: { path } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setSeeded(false);
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "templates"] });
      void qc.invalidateQueries({ queryKey: ["messaging", tenant, "template", channel, event, locale] });
    },
  });
  useEffect(() => {
    if (!tpl.data) return;
    // Nothing: `seeded` gates the initial copy above; this effect only exists so
    // that a reset (which clears `seeded`) reseeds from the refetched template.
  }, [tpl.data]);
  if (tpl.isPending) return <Spinner label="Loading template…" />;
  if (tpl.isError) return <ErrorLine error={tpl.error} />;
  return (
    <div className="flex flex-col gap-4">
      <Card
        title={`${event} · ${channel} · ${locale}`}
        actions={tpl.data.source === "override" ? <Badge tone="accent">Tenant override</Badge> : <Badge>Built-in</Badge>}
      >
        <div className="flex flex-col gap-3">
          {channel === "email" && <Field label="Subject">{(id) => <TextInput id={id} value={subject} disabled={!editable} onChange={(e) => setSubject(e.target.value)} />}</Field>}
          <Field label="Text body" hint="Handlebars; variables: user, tenant, link, code, client, …">
            {(id, by) => <TextArea id={id} aria-describedby={by} value={text} disabled={!editable} onChange={(e) => setText(e.target.value)} className="min-h-40" />}
          </Field>
          {channel === "email" && (
            <Field label="HTML body" hint="Optional; the text body is sent when empty.">
              {(id, by) => <TextArea id={id} aria-describedby={by} value={html} disabled={!editable} onChange={(e) => setHtml(e.target.value)} className="min-h-32" />}
            </Field>
          )}
          {editable && (
            <div className="flex flex-wrap gap-2">
              <Button variant="primary" disabled={save.isPending || !text.trim()} onClick={() => save.mutate()}>
                {save.isPending ? "Saving…" : "Save override"}
              </Button>
              {tpl.data.source === "override" && (
                <Button variant="danger" disabled={reset.isPending} onClick={() => reset.mutate()}>
                  Reset to built-in
                </Button>
              )}
              {save.isSuccess && (
                <span role="status" className="self-center text-[0.8125rem] text-ok">
                  Saved.
                </span>
              )}
            </div>
          )}
          <ErrorLine error={save.error ?? reset.error} />
        </div>
      </Card>
      <Card title="Preview" actions={preview.isFetching ? <span className="text-[0.75rem] text-muted">Rendering…</span> : undefined}>
        {preview.isError ? (
          <ErrorLine error={preview.error} />
        ) : preview.data ? (
          <div className="flex flex-col gap-3">
            {preview.data.subject && <p className="text-[0.9375rem] font-semibold text-ink">{preview.data.subject}</p>}
            <pre className="whitespace-pre-wrap rounded-[var(--radius)] bg-ground px-3 py-2 font-sans text-[0.875rem] text-ink">{preview.data.body_text}</pre>
            {preview.data.body_html && (
              <div>
                <button type="button" onClick={() => setShowHtml((s) => !s)} aria-expanded={showHtml} className="text-[0.8125rem] text-link underline underline-offset-4">
                  {showHtml ? "Hide HTML rendering" : "Show HTML rendering"}
                </button>
                {showHtml && <iframe title="HTML preview" sandbox="" srcDoc={preview.data.body_html} className="mt-2 h-64 w-full rounded-[var(--radius)] border border-line bg-white" />}
              </div>
            )}
            <details className="text-[0.8125rem] text-muted">
              <summary className="cursor-pointer">Sample variables</summary>
              <pre tabIndex={0} aria-label="Sample variables" className="mt-2 max-h-48 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-[0.75rem] text-ink">
                {JSON.stringify(preview.data.vars, null, 2)}
              </pre>
            </details>
          </div>
        ) : (
          <Spinner label="Rendering…" />
        )}
      </Card>
    </div>
  );
}

function LogTab({ tenant }: { tenant: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const [status, setStatus] = useState<LogEntry["status"] | "">("");
  const log = useQuery({
    queryKey: ["messaging", tenant, "log", status],
    // Quick while something is still on its way, slow once it all settled.
    refetchInterval: (q) => (q.state.data?.some((m) => m.status === "queued" || m.status === "sending") ? 10_000 : 60_000),
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/messaging/log", { params: { path: { slug: tenant }, query: { status: status || undefined, limit: 100 } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const redeliver = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.POST("/admin/tenants/{slug}/messaging/log/{message}/redeliver", { params: { path: { slug: tenant, message: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["messaging", tenant, "log"] }),
  });
  const tone = (s: LogEntry["status"]) => (s === "sent" ? "ok" : s === "dead" ? "danger" : "accent");
  return (
    <Card
      title="Outbound messages"
      actions={
        <SelectInput aria-label="Message status" value={status} onChange={(e) => setStatus(e.target.value as LogEntry["status"] | "")} className="min-h-8 w-auto text-[0.8125rem]">
          <option value="">Any status</option>
          {(["queued", "sending", "sent", "dead"] as const).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </SelectInput>
      }
    >
      <p className="mb-3 text-[0.8125rem] text-muted">Bodies are not kept: they carry links and codes.</p>
      <ErrorLine error={redeliver.error} />
      {log.isPending ? (
        <Spinner label="Loading…" />
      ) : log.isError ? (
        <ErrorLine error={log.error} />
      ) : log.data.length === 0 ? (
        <p className="text-[0.875rem] text-muted">Nothing sent yet.</p>
      ) : (
        <ul className="divide-y divide-line">
          {log.data.map((m) => (
            <li key={m.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-[0.875rem]">
              <span>
                <span className="font-medium text-ink">{m.recipient}</span>
                <Badge tone={tone(m.status)}>{m.status}</Badge>
                <span className="ms-2 text-[0.8125rem] text-muted">
                  {m.channel} · {m.event}
                  {m.subject ? ` · ${m.subject}` : ""} · {formatDate("en", m.created_at)} · attempt {m.attempts}/{m.max_attempts}
                </span>
                {m.last_error && <span className="block text-[0.8125rem] text-danger">{m.last_error}</span>}
              </span>
              {can("ridm:messaging:write") && m.status === "dead" && (
                <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={redeliver.isPending} onClick={() => redeliver.mutate(m.id)}>
                  Redeliver
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
