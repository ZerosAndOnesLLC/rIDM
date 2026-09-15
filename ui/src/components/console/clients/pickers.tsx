"use client";

import { useResourceServers, useScopes } from "@/lib/console/hooks";

/** Checkbox list; `fieldset` keeps the group accessible. */
export function CheckList({ legend, hint, options, value, onChange, disabled }: { legend: string; hint?: string; options: { value: string; label: string; hint?: string }[]; value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="mb-1 text-[0.8125rem] font-medium text-ink">{legend}</legend>
      {hint && <p className="mb-1 text-[0.8125rem] text-muted">{hint}</p>}
      {options.length === 0 && <p className="text-[0.875rem] text-muted">Nothing to choose from.</p>}
      {options.map((o) => (
        <label key={o.value} className="flex items-start gap-2 text-[0.875rem] text-ink">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-[var(--accent)]"
            checked={value.includes(o.value)}
            disabled={disabled}
            onChange={(e) => onChange(e.target.checked ? [...value, o.value] : value.filter((x) => x !== o.value))}
          />
          <span>
            {o.label}
            {o.hint && <span className="ms-2 text-[0.8125rem] text-muted">{o.hint}</span>}
          </span>
        </label>
      ))}
    </fieldset>
  );
}

export function ScopePicker({ tenant, value, onChange, disabled }: { tenant: string; value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  const scopes = useScopes(tenant);
  return (
    <CheckList
      legend="Allowed scopes"
      hint="What the client may ask for; the standard scopes are usually enough."
      options={(scopes.data ?? []).map((s) => ({ value: s.name, label: s.name, hint: s.description ?? undefined }))}
      value={value}
      onChange={onChange}
      disabled={disabled}
    />
  );
}

export function AudiencePicker({ tenant, value, onChange, disabled }: { tenant: string; value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  const servers = useResourceServers(tenant);
  return (
    <CheckList
      legend="Allowed audiences"
      hint="Resource servers the client may request tokens for. None means any non-built-in one."
      options={(servers.data ?? []).map((r) => ({ value: r.identifier, label: r.name, hint: r.identifier }))}
      value={value}
      onChange={onChange}
      disabled={disabled}
    />
  );
}
