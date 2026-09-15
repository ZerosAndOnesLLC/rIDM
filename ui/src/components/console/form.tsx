"use client";

import { Check, Loader2, Plus, X } from "lucide-react";
import { useId, useState, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import type { SaveStatus } from "@/lib/console/autosave";

const control =
  "min-h-10 w-full rounded-[var(--radius)] border border-line bg-paper px-3 text-[0.9rem] text-ink placeholder:text-muted/70 hover:border-muted/60 disabled:opacity-60";

/** A titled group of fields on the settings page. */
export function Section({ id, title, description, children }: { id: string; title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-title`} className="scroll-mt-20 rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
      <header className="border-b border-line px-5 py-4">
        <h2 id={`${id}-title`} className="text-[1rem] font-semibold text-ink">
          {title}
        </h2>
        {description && <p className="mt-1 text-[0.875rem] text-muted">{description}</p>}
      </header>
      <div className="grid gap-5 px-5 py-5 sm:grid-cols-2">{children}</div>
    </section>
  );
}

/** Label, control, hint and error, laid out as one grid cell (or two with `wide`). */
export function Field({
  label,
  hint,
  error,
  wide = false,
  children,
  htmlFor,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  wide?: boolean;
  children: (id: string, describedBy: string | undefined) => ReactNode;
  htmlFor?: string;
}) {
  const auto = useId();
  const id = htmlFor ?? auto;
  const describedBy = [error ? `${id}-err` : null, hint ? `${id}-hint` : null].filter(Boolean).join(" ") || undefined;
  return (
    <div className={`flex flex-col gap-1.5 ${wide ? "sm:col-span-2" : ""}`}>
      <label htmlFor={id} className="text-[0.8125rem] font-medium text-ink">
        {label}
      </label>
      {children(id, describedBy)}
      {error ? (
        <p id={`${id}-err`} className="text-[0.8125rem] text-danger" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-[0.8125rem] text-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function TextInput({ className = "", ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`${control} ${className}`} {...rest} />;
}

export function TextArea({ className = "", ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={`${control} min-h-24 py-2 font-mono text-[0.8125rem] ${className}`} {...rest} />;
}

export function SelectInput({ className = "", children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={`${control} ${className}`} {...rest}>
      {children}
    </select>
  );
}

/**
 * Integer input that only reports valid values: the field keeps what was
 * typed and shows the problem until it parses (or is cleared, when nullable).
 */
export function NumberInput({
  id,
  value,
  onValue,
  min = 0,
  max,
  nullable = false,
  describedBy,
  unit,
}: {
  id: string;
  value: number | null;
  onValue: (v: number | null) => void;
  min?: number;
  max?: number;
  nullable?: boolean;
  describedBy?: string;
  unit?: string;
}) {
  const [text, setText] = useState(value === null ? "" : String(value));
  const [seen, setSeen] = useState(value);
  if (seen !== value) {
    setSeen(value);
    setText(value === null ? "" : String(value));
  }
  const invalid = text.trim() === "" ? !nullable : !/^-?\d+$/.test(text.trim()) || Number(text) < min || (max !== undefined && Number(text) > max);
  return (
    <div className="relative">
      <input
        id={id}
        inputMode="numeric"
        aria-invalid={invalid || undefined}
        aria-describedby={describedBy}
        value={text}
        onChange={(e) => {
          const t = e.target.value;
          setText(t);
          if (t.trim() === "") {
            if (nullable) onValue(null);
            return;
          }
          if (/^-?\d+$/.test(t.trim())) {
            const n = Number(t);
            if (n >= min && (max === undefined || n <= max)) onValue(n);
          }
        }}
        className={`${control} ${unit ? "pe-16" : ""} ${invalid ? "border-danger" : ""}`}
      />
      {unit && <span className="pointer-events-none absolute inset-y-0 end-3 flex items-center text-[0.8125rem] text-muted">{unit}</span>}
    </div>
  );
}

/** On/off switch with its label beside it; fills one grid cell. */
export function Toggle({ label, hint, checked, onChange, disabled }: { label: string; hint?: ReactNode; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="flex items-start justify-between gap-4 py-1">
      <span className="flex flex-col">
        <span id={`${id}-l`} className="text-[0.9rem] text-ink">
          {label}
        </span>
        {hint && (
          <span id={`${id}-h`} className="text-[0.8125rem] text-muted">
            {hint}
          </span>
        )}
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-labelledby={`${id}-l`}
        aria-describedby={hint ? `${id}-h` : undefined}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative mt-0.5 h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-60 ${checked ? "bg-accent" : "bg-line"}`}
      >
        <span className={`absolute top-0.5 size-5 rounded-full bg-white shadow transition-[inset-inline-start] ${checked ? "start-[1.375rem]" : "start-0.5"}`} />
      </button>
    </div>
  );
}

/** A list of short strings (domains, roles): chips plus an input; Enter or comma adds. */
export function TagsInput({
  id,
  value,
  onChange,
  placeholder,
  describedBy,
  normalize = (s) => s.trim(),
}: {
  id: string;
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  describedBy?: string;
  normalize?: (s: string) => string;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const parts = draft
      .split(/[,\s]+/)
      .map(normalize)
      .filter(Boolean);
    if (parts.length === 0) return;
    const next = [...value];
    for (const p of parts) if (!next.includes(p)) next.push(p);
    onChange(next);
    setDraft("");
  };
  return (
    <div className={`${control} flex min-h-10 flex-wrap items-center gap-1.5 py-1.5`}>
      {value.map((v) => (
        <span key={v} className="inline-flex items-center gap-1 rounded-md bg-ground px-2 py-0.5 text-[0.8125rem] text-ink">
          {v}
          <button
            type="button"
            aria-label={`Remove ${v}`}
            onClick={() => onChange(value.filter((x) => x !== v))}
            className="rounded p-0.5 text-muted hover:text-ink"
          >
            <X className="size-3" aria-hidden />
          </button>
        </span>
      ))}
      <input
        id={id}
        value={draft}
        aria-describedby={describedBy}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            add();
          } else if (e.key === "Backspace" && draft === "" && value.length > 0) {
            onChange(value.slice(0, -1));
          }
        }}
        onBlur={add}
        placeholder={value.length === 0 ? placeholder : undefined}
        className="min-w-[8rem] flex-1 bg-transparent text-[0.9rem] text-ink outline-none placeholder:text-muted/70"
      />
      {draft && (
        <button type="button" aria-label="Add" onClick={add} className="rounded p-1 text-muted hover:text-ink">
          <Plus className="size-4" aria-hidden />
        </button>
      )}
    </div>
  );
}

/** CSS colour with a native picker alongside; empty means "not set". */
export function ColorInput({ id, value, onChange, describedBy }: { id: string; value: string | null; onChange: (v: string | null) => void; describedBy?: string }) {
  const hex = /^#[0-9a-f]{6}$/i.test(value ?? "") ? value! : "#000000";
  return (
    <div className="flex items-center gap-2">
      <input
        type="color"
        aria-label="Pick a colour"
        value={hex}
        onChange={(e) => onChange(e.target.value)}
        className="size-10 shrink-0 cursor-pointer rounded-[var(--radius)] border border-line bg-paper p-1"
      />
      <input
        id={id}
        value={value ?? ""}
        aria-describedby={describedBy}
        onChange={(e) => onChange(e.target.value.trim() === "" ? null : e.target.value)}
        placeholder="#3451b2"
        spellCheck={false}
        className={control}
      />
    </div>
  );
}

/** "Saving… / Saved / Could not save" pill for the page header. */
export function SaveIndicator({ status, error }: { status: SaveStatus; error: string | null }) {
  if (status === "idle") return <span className="text-[0.8125rem] text-muted">Changes save automatically</span>;
  if (status === "error") {
    return (
      <span role="alert" className="inline-flex items-center gap-1.5 rounded-full bg-danger-soft px-2.5 py-1 text-[0.8125rem] text-danger">
        <X className="size-3.5" aria-hidden />
        {error ?? "Could not save"}
      </span>
    );
  }
  if (status === "saved") {
    return (
      <span role="status" className="inline-flex items-center gap-1.5 rounded-full bg-ok-soft px-2.5 py-1 text-[0.8125rem] text-ok">
        <Check className="size-3.5" aria-hidden />
        Saved
      </span>
    );
  }
  return (
    <span role="status" className="inline-flex items-center gap-1.5 text-[0.8125rem] text-muted">
      <Loader2 className="size-3.5 animate-spin" aria-hidden />
      {status === "saving" ? "Saving…" : "Unsaved changes"}
    </span>
  );
}
