"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Trash2, X } from "lucide-react";
import { useCallback, useMemo, useState, type FormEvent } from "react";
import type { Schemas } from "@api/client";
import { SaveIndicator, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, IconButton, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useAutoSave } from "@/lib/console/autosave";
import { useConsole } from "@/lib/console/session";

type Flag = Schemas["FeatureFlag"];
type Flags = Record<string, Flag>;
/** A merge patch of `settings.features`: `null` removes. */
type FlagsPatch = Record<string, Partial<Omit<Flag, "organizations">> & { organizations?: Record<string, boolean | null> } | null>;

const KEY = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const DESCRIPTION_MAX = 500;

/**
 * Feature flags: each on or off for the whole tenant, optionally with a
 * different value for particular organizations. Applications read the ones
 * that are on through the `features` scope or `GET /t/{slug}/features`.
 */
export function FeatureFlagsPage({ tenant }: { tenant: string }) {
  const { client } = useConsole();
  const [generation, setGeneration] = useState(0);
  const query = useQuery({
    queryKey: ["tenant", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  if (query.isError) {
    return (
      <>
        <PageHeader title="Feature flags" />
        <p role="alert" className="text-[0.9rem] text-danger">
          {query.error.message}
        </p>
      </>
    );
  }
  if (!query.data) return <Spinner label="Loading feature flags…" />;
  // A failed save reloads the stored flags into a fresh editor.
  return <Editor key={`${tenant}:${generation}`} tenant={tenant} initial={query.data.settings.features ?? {}} onReload={() => setGeneration((g) => g + 1)} />;
}

function Editor({ tenant, initial, onReload }: { tenant: string; initial: Flags; onReload: () => void }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const editable = can("ridm:tenants:write");
  const [flags, setFlags] = useState<Flags>(initial);
  const [filter, setFilter] = useState("");
  const orgs = useQuery({
    queryKey: ["organizations", tenant, "slugs"],
    enabled: can("ridm:orgs:read"),
    staleTime: 60_000,
    queryFn: async () => {
      const { data } = await client.GET("/admin/tenants/{slug}/organizations", { params: { path: { slug: tenant }, query: { limit: 200 } } });
      return (data?.items ?? []).map((o) => o.slug).sort();
    },
  });

  const save = useCallback(
    async (patch: FlagsPatch, { keepalive }: { keepalive?: boolean }) => {
      const { error } = await client.PATCH("/admin/tenants/{slug}", { params: { path: { slug: tenant } }, body: { display_name: null, status: null, settings: { features: patch } }, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["tenant", tenant] });
        onReload();
        throw new Error(error.detail ?? error.title);
      }
      void qc.invalidateQueries({ queryKey: ["tenant", tenant] });
    },
    [client, qc, tenant, onReload],
  );
  const { queue, status, error } = useAutoSave<FlagsPatch>(save);

  const change = (key: string, next: Flag | null, patch: FlagsPatch[string]) => {
    setFlags((f) => {
      const copy = { ...f };
      if (next === null) delete copy[key];
      else copy[key] = next;
      return copy;
    });
    queue({ [key]: patch });
  };

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return Object.entries(flags)
      .filter(([k, f]) => !q || k.includes(q) || (f.description ?? "").toLowerCase().includes(q))
      .sort(([a], [b]) => a.localeCompare(b));
  }, [flags, filter]);

  return (
    <>
      <PageHeader title="Feature flags" sub="Switches your applications read, for everyone or per organization." actions={<SaveIndicator status={status} error={error} />} />
      <p className="mb-5 max-w-3xl text-[0.875rem] text-muted">
        An application asks for the <code className="font-mono text-[0.8125rem] text-ink">features</code> scope to get a <code className="font-mono text-[0.8125rem] text-ink">features</code> claim listing the flags that are on for the signed-in user, or calls{" "}
        <code className="font-mono text-[0.8125rem] text-ink">GET /t/{tenant}/features</code> with any access token of this tenant to read them live. A flag that doesn&apos;t exist reads as off.
      </p>
      {editable && <AddFlag existing={flags} onAdd={(key, description) => change(key, { enabled: false, description: description || undefined }, { enabled: false, description: description || null })} />}
      {Object.keys(flags).length > 6 && (
        <label className="relative mb-4 block max-w-sm">
          <Search className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
          <span className="sr-only">Filter flags</span>
          <TextInput value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter flags" className="ps-9" />
        </label>
      )}
      {Object.keys(flags).length === 0 ? (
        <Card>
          <p className="text-[0.875rem] text-muted">No feature flags yet.{editable ? " Add one above; it starts off." : ""}</p>
        </Card>
      ) : shown.length === 0 ? (
        <p className="text-[0.875rem] text-muted">No flag matches “{filter}”.</p>
      ) : (
        <ul className="flex flex-col gap-3">
          {shown.map(([key, flag]) => (
            <li key={key}>
              <FlagCard
                name={key}
                flag={flag}
                editable={editable}
                orgSlugs={orgs.data ?? []}
                onChange={(next, patch) => change(key, next, patch)}
                onRemove={() => change(key, null, null)}
              />
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function AddFlag({ existing, onAdd }: { existing: Flags; onAdd: (key: string, description: string) => void }) {
  const [key, setKey] = useState("");
  const [description, setDescription] = useState("");
  const k = key.trim();
  const problem = !k ? null : !KEY.test(k) ? "Lowercase letters, digits, dots, underscores and hyphens; start with a letter or digit." : k in existing ? "That flag already exists." : null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!k || problem) return;
    onAdd(k, description.trim());
    setKey("");
    setDescription("");
  };
  return (
    <form onSubmit={submit} className="mb-5 flex flex-col gap-2 rounded-[calc(var(--radius)+2px)] border border-line bg-paper p-4 sm:flex-row sm:items-start">
      <div className="flex min-w-0 flex-col gap-1 sm:w-64">
        <label htmlFor="new-flag-key" className="text-[0.8125rem] font-medium text-ink">
          New flag
        </label>
        <TextInput id="new-flag-key" value={key} onChange={(e) => setKey(e.target.value)} placeholder="checkout.v2" autoComplete="off" spellCheck={false} aria-invalid={problem ? true : undefined} aria-describedby={problem ? "new-flag-problem" : undefined} className="font-mono" />
        {problem && (
          <p id="new-flag-problem" className="text-[0.8125rem] text-danger">
            {problem}
          </p>
        )}
      </div>
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <label htmlFor="new-flag-description" className="text-[0.8125rem] font-medium text-ink">
          Description <span className="font-normal text-muted">(optional)</span>
        </label>
        <TextInput id="new-flag-description" value={description} maxLength={DESCRIPTION_MAX} onChange={(e) => setDescription(e.target.value)} placeholder="What turning it on changes" />
      </div>
      <Button type="submit" variant="primary" disabled={!k || Boolean(problem)} className="sm:mt-6">
        <Plus className="size-4" aria-hidden />
        Add
      </Button>
    </form>
  );
}

function FlagCard({
  name,
  flag,
  editable,
  orgSlugs,
  onChange,
  onRemove,
}: {
  name: string;
  flag: Flag;
  editable: boolean;
  orgSlugs: string[];
  onChange: (next: Flag, patch: FlagsPatch[string]) => void;
  onRemove: () => void;
}) {
  const [org, setOrg] = useState("");
  const overrides = Object.entries(flag.organizations ?? {}).sort(([a], [b]) => a.localeCompare(b));
  const slug = org.trim().toLowerCase();
  const canAdd = Boolean(slug) && !(slug in (flag.organizations ?? {}));
  const listId = `orgs-${name}`;
  const setOrgValue = (s: string, v: boolean | null) => {
    const organizations = { ...(flag.organizations ?? {}) };
    if (v === null) delete organizations[s];
    else organizations[s] = v;
    onChange({ ...flag, organizations }, { organizations: { [s]: v } });
  };

  return (
    <Card
      title={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="font-mono text-[0.9375rem]">{name}</span>
          <Badge tone={flag.enabled ? "ok" : "neutral"}>{flag.enabled ? "On" : "Off"}</Badge>
          {overrides.length > 0 && <Badge tone="accent">{overrides.length} organization{overrides.length === 1 ? "" : "s"}</Badge>}
        </span>
      }
      actions={
        editable ? (
          <IconButton label={`Remove ${name}`} onClick={onRemove} className="text-danger hover:bg-danger-soft">
            <Trash2 className="size-4" aria-hidden />
          </IconButton>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-4">
        <Toggle label="On for everyone" hint="Unless an organization below says otherwise." checked={flag.enabled} disabled={!editable} onChange={(v) => onChange({ ...flag, enabled: v }, { enabled: v })} />
        <div className="flex flex-col gap-1">
          <label htmlFor={`desc-${name}`} className="text-[0.8125rem] font-medium text-ink">
            Description
          </label>
          <TextInput
            id={`desc-${name}`}
            value={flag.description ?? ""}
            maxLength={DESCRIPTION_MAX}
            disabled={!editable}
            placeholder="What turning it on changes"
            onChange={(e) => {
              const d = e.target.value;
              onChange({ ...flag, description: d || undefined }, { description: d.trim() ? d : null });
            }}
          />
        </div>
        <div className="flex flex-col gap-2">
          <h3 className="text-[0.8125rem] font-medium text-ink">Per organization</h3>
          {overrides.length === 0 && <p className="text-[0.8125rem] text-muted">Every organization follows the value above.</p>}
          {overrides.length > 0 && (
            <ul className="flex flex-col divide-y divide-line rounded-[var(--radius)] border border-line px-3">
              {overrides.map(([s, on]) => (
                <li key={s} className="flex items-center gap-3">
                  <div className="min-w-0 flex-1">
                    <Toggle label={s} checked={on} disabled={!editable} onChange={(v) => setOrgValue(s, v)} />
                  </div>
                  {editable && (
                    <IconButton label={`Stop overriding for ${s}`} onClick={() => setOrgValue(s, null)}>
                      <X className="size-4" aria-hidden />
                    </IconButton>
                  )}
                </li>
              ))}
            </ul>
          )}
          {editable && (
            <form
              className="flex flex-wrap gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (!canAdd) return;
                setOrgValue(slug, !flag.enabled);
                setOrg("");
              }}
            >
              <TextInput aria-label={`Organization slug for ${name}`} list={listId} value={org} onChange={(e) => setOrg(e.target.value)} placeholder="organization slug" className="max-w-56 font-mono" autoComplete="off" spellCheck={false} />
              <datalist id={listId}>
                {orgSlugs.map((s) => (
                  <option key={s} value={s} />
                ))}
              </datalist>
              <Button type="submit" disabled={!canAdd}>
                {flag.enabled ? "Turn off for it" : "Turn on for it"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </Card>
  );
}
