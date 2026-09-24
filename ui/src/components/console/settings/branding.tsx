"use client";

import { Plus, Trash2 } from "lucide-react";
import { useEffect, useRef } from "react";
import { ColorInput, Field, Section, TextArea, TextInput } from "@/components/console/form";
import { Button, IconButton } from "@/components/console/ui";
import { useRowKeys } from "@/lib/console/hooks";
import { isHttpUrl } from "@/lib/console/settings";
import { useSettingsEditor } from "./context";

export const PREVIEW_MESSAGE = "ridm:preview";

/** What the login page accepts as a live override while previewing. */
export interface PreviewMessage {
  type: typeof PREVIEW_MESSAGE;
  display_name: string;
  branding: {
    logo_url: string | null;
    favicon_url: string | null;
    primary_color: string | null;
    background_color: string | null;
    support_url: string | null;
    custom_css: string | null;
    links: { label: string; url: string }[];
  };
}

export function BrandingSection() {
  const { draft, editable, update } = useSettingsEditor();
  const b = draft.settings.branding;
  const links = useRowKeys(b.links.length);
  const urlError = (v: string | null) => (v && !isHttpUrl(v) ? "Enter an http(s) URL." : null);
  const setLink = (i: number, patch: { label?: string; url?: string }) =>
    update({ branding: { links: b.links.map((l, j) => (j === i ? { ...l, ...patch } : l)) } });

  return (
    <div id="branding" className="scroll-mt-20 grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
      <Section id="branding-fields" title="Branding" description="How the login pages look. The preview on the right follows every change.">
        <Field label="Logo URL" hint="Shown above the card; keep it under 40 px tall." error={urlError(b.logo_url)}>
          {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={b.logo_url ?? ""} disabled={!editable} onChange={(e) => update({ branding: { logo_url: e.target.value || null } })} />}
        </Field>
        <Field label="Favicon URL" error={urlError(b.favicon_url)}>
          {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={b.favicon_url ?? ""} disabled={!editable} onChange={(e) => update({ branding: { favicon_url: e.target.value || null } })} />}
        </Field>
        <Field label="Primary colour" hint="Buttons and focus rings.">
          {(id, by) => <ColorInput id={id} describedBy={by} value={b.primary_color} onChange={(v) => update({ branding: { primary_color: v } })} />}
        </Field>
        <Field label="Background colour" hint="Behind the card.">
          {(id, by) => <ColorInput id={id} describedBy={by} value={b.background_color} onChange={(v) => update({ branding: { background_color: v } })} />}
        </Field>
        <Field label="Support URL" hint="A “Help” link in the footer." error={urlError(b.support_url)}>
          {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={b.support_url ?? ""} disabled={!editable} onChange={(e) => update({ branding: { support_url: e.target.value || null } })} />}
        </Field>
        <div className="sm:col-span-2">
          <h3 className="text-[0.8125rem] font-medium text-ink">Footer links</h3>
          <div className="mt-2 flex flex-col gap-2">
            {b.links.map((l, i) => (
              <div key={links.keys[i]} className="flex flex-wrap items-center gap-2">
                <TextInput aria-label={`Link ${i + 1} label`} value={l.label} disabled={!editable} onChange={(e) => setLink(i, { label: e.target.value })} placeholder="Label" className="max-w-[12rem]" />
                <TextInput aria-label={`Link ${i + 1} URL`} type="url" value={l.url} disabled={!editable} onChange={(e) => setLink(i, { url: e.target.value })} placeholder="https://" className="min-w-[12rem] flex-1" />
                {editable && (
                  <IconButton
                    label={`Remove link ${i + 1}`}
                    onClick={() => {
                      links.removeKey(i);
                      update({ branding: { links: b.links.filter((_, j) => j !== i) } });
                    }}
                  >
                    <Trash2 className="size-4" aria-hidden />
                  </IconButton>
                )}
              </div>
            ))}
            {editable && (
              <Button variant="secondary" className="self-start" onClick={() => update({ branding: { links: [...b.links, { label: "", url: "" }] } })}>
                <Plus className="size-4" aria-hidden />
                Add link
              </Button>
            )}
          </div>
        </div>
        <Field label="Custom CSS" hint="Applied to the end-user pages only; use it sparingly." wide>
          {(id, by) => <TextArea id={id} aria-describedby={by} value={b.custom_css ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => update({ branding: { custom_css: e.target.value || null } })} />}
        </Field>
      </Section>
      <LoginPreview message={{ type: PREVIEW_MESSAGE, display_name: draft.display_name, branding: b }} slug={draft.slug} />
    </div>
  );
}

/** The real login page in a frame, told about every draft change. */
function LoginPreview({ slug, message }: { slug: string; message: PreviewMessage }) {
  const frame = useRef<HTMLIFrameElement>(null);
  const latest = useRef(message);
  useEffect(() => {
    latest.current = message;
    frame.current?.contentWindow?.postMessage(message, window.location.origin);
  }, [message]);
  useEffect(() => {
    // The page asks for the draft once it has loaded its stored branding.
    const onMessage = (e: MessageEvent) => {
      if (e.origin !== window.location.origin || e.source !== frame.current?.contentWindow) return;
      if ((e.data as { type?: string })?.type === `${PREVIEW_MESSAGE}:ready`) {
        frame.current?.contentWindow?.postMessage(latest.current, window.location.origin);
      }
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);
  return (
    <aside className="lg:sticky lg:top-20 lg:self-start">
      <div className="overflow-hidden rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5 text-[0.8125rem] text-muted">
          <span>Login page preview</span>
          <span className="flex gap-1" aria-hidden>
            <span className="size-2.5 rounded-full bg-line" />
            <span className="size-2.5 rounded-full bg-line" />
            <span className="size-2.5 rounded-full bg-line" />
          </span>
        </div>
        <iframe
          ref={frame}
          title="Login page preview"
          src={`/login/?tenant=${encodeURIComponent(slug)}&preview=1`}
          className="h-[34rem] w-full bg-ground"
          sandbox="allow-scripts allow-same-origin"
        />
      </div>
    </aside>
  );
}
