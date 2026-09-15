"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { useCallback, useState } from "react";
import { Field, NumberInput, SaveIndicator, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { Button, IconButton } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useAutoSave } from "@/lib/console/autosave";
import { useConsole } from "@/lib/console/session";
import type { AttributeDef, ProfileSchema } from "@/lib/console/users";
import { CheckList } from "../clients/pickers";

const TYPES = ["string", "number", "boolean", "email", "url", "phone", "date", "enum", "json"] as const;

function blank(order: number): AttributeDef {
  return { name: "", type: "string", label: null, description: null, required: false, multivalued: false, editable_by: "user", visible_in: [], validation: { min_length: null, max_length: null, pattern: null, min: null, max: null, values: [] }, order };
}

/**
 * The tenant's profile schema: which attributes users carry, typed and
 * validated, who may edit them and where they surface. Saved whole
 * (`PUT`), as you go.
 */
export function ProfileSchemaSection({ tenant, editable }: { tenant: string; editable: boolean }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["profile-schema", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/profile-schema", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<ProfileSchema | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);

  const save = useCallback(
    async (schema: ProfileSchema, { keepalive }: { keepalive?: boolean }) => {
      const { data, error } = await client.PUT("/admin/tenants/{slug}/profile-schema", { params: { path: { slug: tenant } }, body: schema, keepalive });
      if (error) {
        const fields = error.errors?.map((e) => `${e.field}: ${e.message}`).join("; ");
        throw new Error(fields || error.detail || error.title);
      }
      qc.setQueryData(["profile-schema", tenant], data);
    },
    [client, qc, tenant],
  );
  const { queue, status, error } = useAutoSave<ProfileSchema>(save);
  const update = (next: ProfileSchema) => {
    setDraft(next);
    if (editable) queue(next);
  };
  const reload = useMutation({
    mutationFn: async () => {
      await qc.invalidateQueries({ queryKey: ["profile-schema", tenant] });
      setResetCount((n) => n + 1);
    },
  });

  if (query.isError)
    return (
      <p role="alert" className="text-[0.875rem] text-danger">
        {query.error.message}
      </p>
    );
  if (!draft) return <Spinner label="Loading schema…" />;
  const attrs = draft.attributes;
  const setAttr = (i: number, patch: Partial<AttributeDef>) => update({ ...draft, attributes: attrs.map((a, j) => (j === i ? { ...a, ...patch } : a)) });
  const setValidation = (i: number, patch: Partial<AttributeDef["validation"]>) => setAttr(i, { validation: { ...attrs[i]!.validation, ...patch } });

  return (
    <section id="profile" aria-labelledby="profile-title" className="scroll-mt-20 rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4">
        <div>
          <h2 id="profile-title" className="text-[1rem] font-semibold text-ink">
            Profile attributes
          </h2>
          <p className="mt-1 text-[0.875rem] text-muted">What a user profile carries beyond username, email and phone. Names cannot change once values exist.</p>
        </div>
        <span className="flex items-center gap-2">
          <SaveIndicator status={status} error={error} />
          {status === "error" && (
            <Button className="min-h-8 px-2.5 text-[0.8125rem]" onClick={() => reload.mutate()}>
              Reload
            </Button>
          )}
        </span>
      </header>
      <div className="flex flex-col gap-4 px-5 py-5">
        <Toggle label="Accept undeclared attributes" hint="Stored verbatim; only administrators, imports and mappers can set them." checked={draft.allow_undeclared} disabled={!editable} onChange={(v) => update({ ...draft, allow_undeclared: v })} />
        {attrs.length === 0 && <p className="text-[0.875rem] text-muted">No attributes declared.</p>}
        {attrs.map((a, i) => (
          <div key={i} className="rounded-[var(--radius)] border border-line p-4" data-testid="attribute-row">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name" hint="Lowercase letters, digits and underscores.">
                {(id, by) => <TextInput id={id} aria-describedby={by} value={a.name} disabled={!editable} autoCapitalize="none" spellCheck={false} onChange={(e) => setAttr(i, { name: e.target.value })} />}
              </Field>
              <Field label="Type">
                {(id) => (
                  <SelectInput id={id} value={a.type} disabled={!editable} onChange={(e) => setAttr(i, { type: e.target.value as AttributeDef["type"] })}>
                    {TYPES.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </SelectInput>
                )}
              </Field>
              <Field label="Label">{(id) => <TextInput id={id} value={a.label ?? ""} disabled={!editable} onChange={(e) => setAttr(i, { label: e.target.value || null })} />}</Field>
              <Field label="Description">{(id) => <TextInput id={id} value={a.description ?? ""} disabled={!editable} onChange={(e) => setAttr(i, { description: e.target.value || null })} />}</Field>
              <Field label="Editable by">
                {(id) => (
                  <SelectInput id={id} value={a.editable_by} disabled={!editable} onChange={(e) => setAttr(i, { editable_by: e.target.value as AttributeDef["editable_by"] })}>
                    <option value="user">The user and administrators</option>
                    <option value="admin">Administrators only</option>
                    <option value="none">Nobody (imports and mappers)</option>
                  </SelectInput>
                )}
              </Field>
              <Field label="Position" hint="Order in forms.">
                {(id, by) => <NumberInput id={id} describedBy={by} value={a.order} min={0} onValue={(v) => v !== null && setAttr(i, { order: v })} />}
              </Field>
              <div className="flex flex-col gap-1">
                <Toggle label="Required" checked={a.required} disabled={!editable} onChange={(v) => setAttr(i, { required: v })} />
                <Toggle label="Multiple values" checked={a.multivalued} disabled={!editable} onChange={(v) => setAttr(i, { multivalued: v })} />
              </div>
              <CheckList
                legend="Included in"
                options={[
                  { value: "id_token", label: "ID token" },
                  { value: "userinfo", label: "userinfo" },
                  { value: "access_token", label: "Access token" },
                ]}
                value={a.visible_in}
                onChange={(v) => setAttr(i, { visible_in: v as AttributeDef["visible_in"] })}
                disabled={!editable}
              />
              {a.type === "enum" && (
                <Field label="Allowed values" hint="Enter adds one." wide>
                  {(id, by) => <TagsInput id={id} describedBy={by} value={a.validation.values} onChange={(v) => setValidation(i, { values: v })} placeholder="eng, sales" />}
                </Field>
              )}
              {(a.type === "string" || a.type === "email" || a.type === "url" || a.type === "phone") && (
                <>
                  <Field label="Minimum length">{(id) => <NumberInput id={id} value={a.validation.min_length ?? null} min={0} nullable onValue={(v) => setValidation(i, { min_length: v })} />}</Field>
                  <Field label="Maximum length">{(id) => <NumberInput id={id} value={a.validation.max_length ?? null} min={0} nullable onValue={(v) => setValidation(i, { max_length: v })} />}</Field>
                  <Field label="Pattern" hint="Anchored regular expression." wide>
                    {(id, by) => <TextInput id={id} aria-describedby={by} value={a.validation.pattern ?? ""} disabled={!editable} spellCheck={false} onChange={(e) => setValidation(i, { pattern: e.target.value || null })} />}
                  </Field>
                </>
              )}
              {a.type === "number" && (
                <>
                  <Field label="Minimum">
                    {(id) => <TextInput id={id} inputMode="decimal" value={a.validation.min ?? ""} disabled={!editable} onChange={(e) => setValidation(i, { min: e.target.value.trim() === "" ? null : Number(e.target.value) })} />}
                  </Field>
                  <Field label="Maximum">
                    {(id) => <TextInput id={id} inputMode="decimal" value={a.validation.max ?? ""} disabled={!editable} onChange={(e) => setValidation(i, { max: e.target.value.trim() === "" ? null : Number(e.target.value) })} />}
                  </Field>
                </>
              )}
            </div>
            {editable && (
              <div className="mt-3 flex justify-end">
                <IconButton label={`Remove attribute ${a.name || i + 1}`} className="text-danger hover:bg-danger-soft" onClick={() => update({ ...draft, attributes: attrs.filter((_, j) => j !== i) })}>
                  <Trash2 className="size-4" aria-hidden />
                </IconButton>
              </div>
            )}
          </div>
        ))}
        {editable && (
          <Button variant="secondary" className="self-start" onClick={() => setDraft({ ...draft, attributes: [...attrs, blank(attrs.length)] })}>
            <Plus className="size-4" aria-hidden />
            Add attribute
          </Button>
        )}
      </div>
    </section>
  );
}
