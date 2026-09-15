"use client";

import { Field, SelectInput, TagsInput, TextArea, TextInput, Toggle } from "@/components/console/form";
import { attrToText, type AttributeDef } from "@/lib/console/users";

/**
 * One profile attribute as its schema declares it: the right control for
 * the type, `editable_by: none` read-only, multivalued as a tag list.
 */
export function AttributeField({ def, value, onChange, disabled }: { def: AttributeDef; value: unknown; onChange: (v: unknown) => void; disabled: boolean }) {
  const label = def.label ?? def.name;
  const ro = disabled || def.editable_by === "none";
  const hint = [def.description, def.required ? "Required." : null, def.editable_by === "none" ? "Set by imports or mappers only." : null].filter(Boolean).join(" ");

  if (def.multivalued) {
    const list = Array.isArray(value) ? value.map((v) => attrToText(v)) : [];
    return (
      <Field label={label} hint={hint || undefined} wide>
        {(id, by) => <TagsInput id={id} describedBy={by} value={list} onChange={(v) => onChange(v.length ? (def.type === "number" ? v.map(Number) : v) : null)} placeholder={def.type === "enum" ? def.validation.values.join(", ") : undefined} />}
      </Field>
    );
  }
  switch (def.type) {
    case "boolean":
      return <Toggle label={label} hint={hint || undefined} checked={value === true} disabled={ro} onChange={(v) => onChange(v)} />;
    case "enum":
      return (
        <Field label={label} hint={hint || undefined}>
          {(id, by) => (
            <SelectInput id={id} aria-describedby={by} value={attrToText(value)} disabled={ro} onChange={(e) => onChange(e.target.value === "" ? null : e.target.value)}>
              <option value="">—</option>
              {def.validation.values.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
      );
    case "json":
      return (
        <Field label={label} hint={hint || "JSON"} wide>
          {(id, by) => <JsonInput id={id} describedBy={by} value={value} onChange={onChange} disabled={ro} />}
        </Field>
      );
    case "number":
      return (
        <Field label={label} hint={hint || undefined}>
          {(id, by) => (
            <TextInput
              id={id}
              aria-describedby={by}
              inputMode="decimal"
              value={attrToText(value)}
              disabled={ro}
              onChange={(e) => {
                const t = e.target.value.trim();
                if (t === "") onChange(null);
                else if (!Number.isNaN(Number(t))) onChange(Number(t));
              }}
            />
          )}
        </Field>
      );
    default:
      return (
        <Field label={label} hint={hint || undefined}>
          {(id, by) => (
            <TextInput
              id={id}
              aria-describedby={by}
              type={def.type === "email" ? "email" : def.type === "url" ? "url" : def.type === "phone" ? "tel" : def.type === "date" ? "date" : "text"}
              value={attrToText(value)}
              disabled={ro}
              onChange={(e) => onChange(e.target.value === "" ? null : e.target.value)}
            />
          )}
        </Field>
      );
  }
}

/** Free-form JSON that only reports parsable values. */
export function JsonInput({ id, describedBy, value, onChange, disabled }: { id: string; describedBy?: string; value: unknown; onChange: (v: unknown) => void; disabled?: boolean }) {
  const text = value === null || value === undefined ? "" : JSON.stringify(value, null, 2);
  return (
    <TextArea
      id={id}
      aria-describedby={describedBy}
      defaultValue={text}
      disabled={disabled}
      spellCheck={false}
      onBlur={(e) => {
        const t = e.target.value.trim();
        if (t === "") {
          onChange(null);
          return;
        }
        try {
          onChange(JSON.parse(t));
        } catch {
          // Leave the text as typed; nothing is saved until it parses.
        }
      }}
    />
  );
}
