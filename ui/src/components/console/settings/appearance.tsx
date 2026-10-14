"use client";

import { Check as CheckIcon, Plus, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";
import { ColorInput, Field, Section, TextArea, TextInput, Toggle } from "@/components/console/form";
import { Button, IconButton } from "@/components/console/ui";
import { useRowKeys } from "@/lib/console/hooks";
import { isHttpUrl, type Tenant } from "@/lib/console/settings";
import { SKINS, pairOf, type Skin, type ThemeMode } from "@/lib/theme/appearance";
import { PRESETS, checks, ramp, type Check, type Step } from "@/lib/theme/ramp";
import { useSettingsEditor } from "./context";

export const PREVIEW_MESSAGE = "ridm:preview";

/** What the login page accepts as a live override while previewing. */
export interface PreviewMessage {
  type: typeof PREVIEW_MESSAGE;
  display_name: string;
  branding: Tenant["settings"]["branding"];
}

const STEPS: Step[] = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900];
const LIGHT_PAPER = "#ffffff";
const DARK_PAPER = "#15181f";
const MODES: { value: ThemeMode; label: string; hint: string }[] = [
  { value: "system", label: "Follow each person's device", hint: "Light or dark as their system prefers." },
  { value: "light", label: "Always light", hint: "Best when the brand is built for light surfaces." },
  { value: "dark", label: "Always dark", hint: "" },
];

/**
 * How the tenant looks: skin, the two theme colours (with the shades and
 * readability checks they produce), the light/dark policy, and the logo,
 * links and custom CSS of the sign-in pages. The login page on the right is
 * the real one in preview mode and follows every change.
 */
export function AppearanceSection() {
  const { draft, editable, update } = useSettingsEditor();
  const b = draft.settings.branding;
  const links = useRowKeys(b.links.length);
  const urlError = (v: string | null) => (v && !isHttpUrl(v) ? "Enter an http(s) URL." : null);
  const setLink = (i: number, patch: { label?: string; url?: string }) =>
    update({ branding: { links: b.links.map((l, j) => (j === i ? { ...l, ...patch } : l)) } });

  const pair = useMemo(() => pairOf(b), [b]);
  const preset = PRESETS.find((p) => pair && p.primary === pair.primary && p.contrast === pair.contrast)?.id ?? (pair ? "custom" : "default");
  const ramps = useMemo(() => (pair ? { primary: ramp(pair.primary), contrast: ramp(pair.contrast) } : null), [pair]);
  const results = useMemo(() => (pair ? { light: checks(pair, false, LIGHT_PAPER), dark: checks(pair, true, DARK_PAPER) } : null), [pair]);

  return (
    <div id="appearance" className="scroll-mt-20 grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
      <Section id="appearance-fields" title="Appearance" description="How the sign-in pages, the account console and this console look for the tenant. The preview on the right follows every change.">
        <fieldset className="sm:col-span-2">
          <legend className="text-small font-medium text-ink">Skin</legend>
          <p className="mt-1 text-small text-muted">The layout family and token set. Every page works in all four; Signal v2 is the default.</p>
          <div role="radiogroup" aria-label="Skin" className="mt-2 grid gap-2 sm:grid-cols-2">
            {SKINS.map((s) => (
              <button
                key={s.id}
                type="button"
                role="radio"
                aria-checked={b.skin === s.id}
                disabled={!editable}
                onClick={() => update({ branding: { skin: s.id satisfies Skin } })}
                className={`flex flex-col items-start gap-0.5 rounded-[var(--radius)] border px-3 py-2 text-start ${b.skin === s.id ? "border-accent-ring bg-accent-soft ring-2 ring-accent-soft-2" : "border-line bg-ground hover:border-line-strong"} disabled:cursor-not-allowed disabled:opacity-60`}
              >
                <span className="text-body font-medium text-ink">
                  {s.name}
                  {s.id === "signal-v2" && <span className="ms-2 text-caption font-normal text-muted">default</span>}
                </span>
                <span className="text-caption text-muted">{s.blurb}</span>
              </button>
            ))}
          </div>
        </fieldset>

        <fieldset className="sm:col-span-2">
          <legend className="text-small font-medium text-ink">Colour theme</legend>
          <p className="mt-1 text-small text-muted">A primary colour for actions and navigation, and a contrast colour for selection and the tenant mark. rIDM derives ten shades from each so both modes stay readable.</p>
          <div role="radiogroup" aria-label="Colour theme" className="mt-2 grid gap-2 sm:grid-cols-3">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={preset === p.id}
                disabled={!editable}
                onClick={() => update({ branding: { primary_color: p.primary, contrast_color: p.contrast } })}
                className={`flex items-center gap-2.5 rounded-[var(--radius)] border px-3 py-2 text-start text-body ${preset === p.id ? "border-accent-ring bg-accent-soft ring-2 ring-accent-soft-2" : "border-line bg-ground hover:border-line-strong"} disabled:cursor-not-allowed disabled:opacity-60`}
              >
                <span className="flex" aria-hidden>
                  <i className="size-4 rounded-full border-2 border-paper" style={{ background: p.primary }} />
                  <i className="-ms-1.5 size-4 rounded-full border-2 border-paper" style={{ background: p.contrast }} />
                </span>
                {p.name}
              </button>
            ))}
          </div>
        </fieldset>
        <Field label="Primary colour" hint="Buttons, navigation, links and focus. A hex colour drives every shade.">
          {(id, by) => <ColorInput id={id} describedBy={by} value={b.primary_color} onChange={(v) => update({ branding: { primary_color: v } })} />}
        </Field>
        <Field label="Contrast colour" hint="Selection and the tenant mark. Leave empty to derive it from the primary.">
          {(id, by) => <ColorInput id={id} describedBy={by} value={b.contrast_color} onChange={(v) => update({ branding: { contrast_color: v } })} />}
        </Field>
        {ramps && results && (
          <div className="sm:col-span-2 flex flex-col gap-2">
            <Ramp label="Primary" steps={ramps.primary} />
            <Ramp label="Contrast" steps={ramps.contrast} />
            <ul className="mt-1 grid gap-x-4 gap-y-1 text-caption sm:grid-cols-2" aria-label="Readability checks">
              {results.light.map((c, i) => (
                <CheckRow key={c.label} light={c} dark={results.dark[i]!} />
              ))}
            </ul>
          </div>
        )}

        <fieldset className="sm:col-span-2">
          <legend className="text-small font-medium text-ink">Light and dark</legend>
          <p className="mt-1 text-small text-muted">Applies to the sign-in pages, the account console and this console.</p>
          <div role="radiogroup" aria-label="Light and dark" className="mt-2 grid gap-2">
            {MODES.map((m) => (
              <label key={m.value} className={`flex cursor-pointer items-start gap-3 rounded-[var(--radius)] border px-3 py-2 ${b.mode === m.value ? "border-accent-ring bg-accent-soft" : "border-line"}`}>
                <input type="radio" name="appearance-mode" value={m.value} checked={b.mode === m.value} disabled={!editable} onChange={() => update({ branding: { mode: m.value } })} className="mt-1 accent-[var(--accent-solid)]" />
                <span className="flex flex-col">
                  <span className="text-body text-ink">{m.label}</span>
                  {m.hint && <span className="text-caption text-muted">{m.hint}</span>}
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="sm:col-span-2">
          <Toggle label="People can switch between light and dark" hint="Shows a switch in every console and on the sign-in pages; their choice is remembered on that device." checked={b.allow_theme_switch} disabled={!editable} onChange={(v) => update({ branding: { allow_theme_switch: v } })} />
        </div>

        <Field label="Logo URL" hint="Shown above the card; keep it under 40 px tall." error={urlError(b.logo_url)}>
          {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={b.logo_url ?? ""} disabled={!editable} onChange={(e) => update({ branding: { logo_url: e.target.value || null } })} />}
        </Field>
        <Field label="Headline" hint="With the Signal v2 skin the sign-in page gains a brand panel carrying this line; the other skins keep the single card." wide>
          {(id, by) => <TextInput id={id} aria-describedby={by} maxLength={120} value={b.headline ?? ""} disabled={!editable} onChange={(e) => update({ branding: { headline: e.target.value || null } })} />}
        </Field>
        <Field label="Tagline" hint="A sentence under the headline." wide>
          {(id, by) => <TextInput id={id} aria-describedby={by} maxLength={240} value={b.tagline ?? ""} disabled={!editable} onChange={(e) => update({ branding: { tagline: e.target.value || null } })} />}
        </Field>
        <Field label="Favicon URL" error={urlError(b.favicon_url)}>
          {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={b.favicon_url ?? ""} disabled={!editable} onChange={(e) => update({ branding: { favicon_url: e.target.value || null } })} />}
        </Field>
        <Field label="Background colour" hint="Behind the sign-in card; otherwise the ground takes a tint of the primary.">
          {(id, by) => <ColorInput id={id} describedBy={by} value={b.background_color} onChange={(v) => update({ branding: { background_color: v } })} />}
        </Field>
        <Field label="Support URL" hint="A “Help” link in the footer." error={urlError(b.support_url)}>
          {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={b.support_url ?? ""} disabled={!editable} onChange={(e) => update({ branding: { support_url: e.target.value || null } })} />}
        </Field>
        <div className="sm:col-span-2">
          <h3 className="text-small font-medium text-ink">Footer links</h3>
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

function Ramp({ label, steps }: { label: string; steps: Record<Step, string> }) {
  return (
    <div className="grid grid-cols-[4.5rem_1fr] items-center gap-2 text-caption text-muted">
      <span>{label}</span>
      <div className="grid h-7 grid-cols-10 overflow-hidden rounded-[var(--radius-sm)]" role="img" aria-label={`${label} shades 50 to 900: ${STEPS.map((s) => steps[s]).join(", ")}`}>
        {STEPS.map((s) => (
          <i key={s} className="block" style={{ background: steps[s] }} title={`${s} ${steps[s]}`} />
        ))}
      </div>
    </div>
  );
}

/** One check, with the light and dark values side by side. */
function CheckRow({ light, dark }: { light: Check; dark: Check }) {
  const fmt = (c: Check) => (c.kind === "ratio" ? `${c.value.toFixed(1)}:1` : `${Math.round(c.value)}°`);
  const pass = light.pass && dark.pass;
  return (
    <li className={`flex items-center gap-1.5 ${pass ? "text-ok" : "text-danger"}`}>
      {pass ? <CheckIcon className="size-3.5" aria-hidden /> : <X className="size-3.5" aria-hidden />}
      <span className="font-mono text-ink">{light.kind === "degrees" ? fmt(light) : `${fmt(light)} / ${fmt(dark)}`}</span>
      <span className="text-muted">
        {light.label}
        {light.kind === "ratio" && " (light / dark)"}
        {!pass && " — under 4.5:1"}
      </span>
    </li>
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
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5 text-small text-muted">
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
