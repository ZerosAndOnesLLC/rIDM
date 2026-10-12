"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, RotateCw } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/base/confirm-dialog";
import { useToast } from "@/components/base/toast";
import { Field, SelectInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, PageHeader, Row } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import type { KeyStatus, SigningKey } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { RSA_BITS, SIGNING_ALGS } from "@/lib/console/settings";
import { CreateDialog, ErrorLine } from "../access/common";

const TONE: Record<KeyStatus, "ok" | "accent" | "neutral" | "danger"> = { active: "ok", pending: "accent", retiring: "neutral", revoked: "danger" };

type KeyAction = { rotate: true } | { id: string; kid: string; op: "activate" | "retire" | "revoke" };

/** What each action asks before it runs, and says once it has. */
const CONFIRM: Record<"rotate" | "retire" | "revoke", { title: string; description: string; label: string; done: string }> = {
  rotate: {
    title: "Rotate the signing key?",
    description: "A new key is created and activated at once; the key that is active now starts retiring with the policy's overlap. Tokens it signed stay valid until they expire.",
    label: "Rotate now",
    done: "Key rotated",
  },
  retire: {
    title: "Retire this key?",
    description: "It stops signing new tokens but stays published until the ones it signed have expired.",
    label: "Retire",
    done: "Key retiring",
  },
  revoke: {
    title: "Revoke this key?",
    description: "It is removed from the JWKS immediately. Every token it signed stops verifying, which ends the sessions that use them.",
    label: "Revoke",
    done: "Key revoked",
  },
};

/** Signing keys as a timeline, with rotation and per-key lifecycle actions. */
export function KeysPage({ tenant }: { tenant: string }) {
  const { client, can, me } = useConsole();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [confirm, setConfirm] = useState<KeyAction | null>(null);
  const { toast } = useToast();
  const keys = useQuery({
    queryKey: ["keys", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/keys", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return { keys: [...data].sort((a, b) => b.not_before.localeCompare(a.not_before)), now: Date.now() };
    },
  });
  const act = useMutation({
    mutationFn: async (what: KeyAction) => {
      const r =
        "rotate" in what
          ? await client.POST("/admin/tenants/{slug}/keys/rotate", { params: { path: { slug: tenant } } })
          : what.op === "activate"
            ? await client.POST("/admin/tenants/{slug}/keys/{key}/activate", { params: { path: { slug: tenant, key: what.id } } })
            : what.op === "retire"
              ? await client.POST("/admin/tenants/{slug}/keys/{key}/retire", { params: { path: { slug: tenant, key: what.id } } })
              : await client.POST("/admin/tenants/{slug}/keys/{key}/revoke", { params: { path: { slug: tenant, key: what.id } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["keys", tenant] }),
  });
  // Activation is reversible enough to run at once; the rest ask first.
  const run = (what: KeyAction) => {
    if ("rotate" in what || what.op !== "activate") setConfirm(what);
    else act.mutate(what);
  };
  const confirmed = confirm ? CONFIRM["rotate" in confirm ? "rotate" : (confirm.op as "retire" | "revoke")] : null;
  const editable = can("ridm:keys:write");
  const now = keys.data?.now ?? 0;
  const all = keys.data?.keys ?? [];
  const span = all.length ? { from: Math.min(...all.map((k) => new Date(k.created_at).getTime())), to: Math.max(now + 86_400_000, ...all.map((k) => (k.expires_at ? new Date(k.expires_at).getTime() : now + 30 * 86_400_000))) } : null;

  return (
    <>
      <PageHeader
        title="Signing keys"
        sub="Keys that sign this tenant's tokens; the JWKS publishes every pending, active and retiring key."
        actions={
          editable ? (
            <>
              <Button onClick={() => setCreating(true)}>
                <Plus className="size-4" aria-hidden />
                New key
              </Button>
              <Button variant="primary" disabled={act.isPending} onClick={() => run({ rotate: true })}>
                <RotateCw className="size-4" aria-hidden />
                Rotate now
              </Button>
            </>
          ) : undefined
        }
      />
      {!confirm && <ErrorLine error={act.error} />}
      {keys.isPending ? (
        <Spinner label="Loading keys…" />
      ) : keys.isError ? (
        <ErrorLine error={keys.error} />
      ) : (
        <div className="flex flex-col gap-4">
          {span && (
            <Card title="Timeline">
              <ol className="flex flex-col gap-2" aria-label="Key timeline">
                {all.map((k) => {
                  const start = ((new Date(k.not_before).getTime() - span.from) / (span.to - span.from)) * 100;
                  const end = (((k.expires_at ? new Date(k.expires_at).getTime() : span.to) - span.from) / (span.to - span.from)) * 100;
                  return (
                    <li key={k.id} className="grid grid-cols-[minmax(0,1fr)] items-center gap-x-3 gap-y-1 text-small sm:grid-cols-[10rem_minmax(0,1fr)]">
                      <span className="truncate font-mono text-muted">{k.kid}</span>
                      <span className="relative h-4 rounded bg-ground" aria-hidden>
                        <span
                          className={`absolute top-0 h-4 rounded ${k.status === "active" ? "bg-ok" : k.status === "pending" ? "bg-accent" : k.status === "retiring" ? "bg-muted" : "bg-danger"}`}
                          style={{ insetInlineStart: `${Math.max(0, Math.min(100, start))}%`, width: `${Math.max(1, Math.min(100, end) - Math.max(0, start))}%` }}
                        />
                      </span>
                    </li>
                  );
                })}
              </ol>
              <span className="mt-2 block text-caption text-muted">
                {formatDate("en", span.from, { dateStyle: "medium" })} → {formatDate("en", span.to, { dateStyle: "medium" })}
              </span>
            </Card>
          )}
          {all.length === 0 && <p className="text-body text-muted">No keys yet; rotate to create the first active key.</p>}
          {all.map((k) => (
            <KeyCard key={k.id} k={k} editable={editable} pending={act.isPending} onAct={(op) => run({ id: k.id, kid: k.kid, op })} />
          ))}
        </div>
      )}
      {me?.scope === "global" && can("ridm:keys:read") && <MasterKey />}
      <CreateKey tenant={tenant} open={creating} onOpenChange={setCreating} />
      {confirm && confirmed && (
        <ConfirmDialog
          open
          onOpenChange={(o) => {
            if (!o) setConfirm(null);
          }}
          title={confirmed.title}
          description={
            "rotate" in confirm ? (
              confirmed.description
            ) : (
              <>
                <span className="font-mono text-ink">{confirm.kid}</span>: {confirmed.description}
              </>
            )
          }
          confirmLabel={confirmed.label}
          tone={"rotate" in confirm ? "primary" : "danger"}
          onConfirm={async () => {
            await act.mutateAsync(confirm);
            toast({ title: confirmed.done, description: "rotate" in confirm ? undefined : confirm.kid });
          }}
        />
      )}
    </>
  );
}

function KeyCard({ k, editable, pending, onAct }: { k: SigningKey; editable: boolean; pending: boolean; onAct: (op: "activate" | "retire" | "revoke") => void }) {
  const [showJwk, setShowJwk] = useState(false);
  return (
    <Card
      title={
        <span className="inline-flex flex-wrap items-center gap-2">
          <KeyRound className="size-4 text-muted" aria-hidden />
          <span className="break-all font-mono">{k.kid}</span>
          <Badge tone={TONE[k.status]}>{k.status}</Badge>
          <Badge>{k.alg}</Badge>
        </span>
      }
      actions={
        editable && k.status !== "revoked" ? (
          <span className="flex gap-1.5">
            {k.status === "pending" && (
              <Button className="min-h-8 px-2.5 text-small" disabled={pending} onClick={() => onAct("activate")}>
                Activate
              </Button>
            )}
            {k.status === "active" && (
              <Button className="min-h-8 px-2.5 text-small" disabled={pending} onClick={() => onAct("retire")}>
                Retire
              </Button>
            )}
            <Button variant="danger" className="min-h-8 px-2.5 text-small" disabled={pending} onClick={() => onAct("revoke")}>
              Revoke
            </Button>
          </span>
        ) : undefined
      }
    >
      <dl>
        <Row label="Created">{formatDate("en", k.created_at)}</Row>
        <Row label="Signs from">{formatDate("en", k.not_before)}</Row>
        <Row label="Published until">{k.expires_at ? formatDate("en", k.expires_at) : k.status === "revoked" ? "Unpublished" : "Until retired"}</Row>
        <Row label="Master-key generation">{k.key_version}</Row>
      </dl>
      <button type="button" onClick={() => setShowJwk((s) => !s)} aria-expanded={showJwk} className="mt-2 text-small text-link underline underline-offset-4">
        {showJwk ? "Hide public key" : "Show public key (JWK)"}
      </button>
      {showJwk && (
        <pre tabIndex={0} aria-label="Public JWK" className="mt-2 max-h-64 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-caption text-ink">
          {JSON.stringify(k.public_jwk, null, 2)}
        </pre>
      )}
    </Card>
  );
}

function CreateKey({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [alg, setAlg] = useState<string>("");
  const [bits, setBits] = useState<string>("");
  const [activate, setActivate] = useState(false);
  const create = useMutation({
    mutationFn: async () => {
      const { error } = await client.POST("/admin/tenants/{slug}/keys", {
        params: { path: { slug: tenant } },
        body: { alg: (alg || null) as never, rsa_bits: bits ? Number(bits) : null, activate, not_before: null },
      });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["keys", tenant] });
      onOpenChange(false);
    },
  });
  return (
    <CreateDialog open={open} onOpenChange={onOpenChange} title="New signing key" description="Published at once; it starts signing when activated." submitLabel="Create key" pending={create.isPending} error={create.error?.message ?? null} onSubmit={() => create.mutate()}>
      <Field label="Algorithm" hint="Empty = the tenant's key policy.">
        {(id, by) => (
          <SelectInput id={id} aria-describedby={by} value={alg} onChange={(e) => setAlg(e.target.value)}>
            <option value="">Policy default</option>
            {SIGNING_ALGS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </SelectInput>
        )}
      </Field>
      {(alg === "" || alg.startsWith("RS")) && (
        <Field label="RSA key size">
          {(id) => (
            <SelectInput id={id} value={bits} onChange={(e) => setBits(e.target.value)}>
              <option value="">Policy default</option>
              {RSA_BITS.map((b) => (
                <option key={b.value} value={b.value.slice(1)}>
                  {b.label}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
      )}
      <Toggle label="Activate immediately" hint="The current active key retires with the policy's overlap." checked={activate} onChange={setActivate} />
    </CreateDialog>
  );
}

function MasterKey() {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: ["master-key"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/master-key");
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const rotate = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/master-key/rotate");
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["master-key"] }),
  });
  const generate = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/master-key/generations");
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["master-key"] }),
  });
  const wrapper = status.data?.key_wrapper ?? null;
  const editable = can("ridm:keys:write");
  return (
    <Card
      title="Master key"
      className="mt-6"
      actions={
        editable ? (
          <span className="flex flex-wrap gap-1.5">
            {wrapper && (
              <Button className="min-h-8 px-2.5 text-small" disabled={generate.isPending} onClick={() => generate.mutate()}>
                New generation
              </Button>
            )}
            <Button className="min-h-8 px-2.5 text-small" disabled={rotate.isPending || (status.data?.pending_rows ?? 0) === 0} onClick={() => rotate.mutate()}>
              Re-encrypt pending rows
            </Button>
          </span>
        ) : undefined
      }
    >
      <p className="mb-3 text-small text-muted">
        {wrapper
          ? `Every secret at rest is encrypted under a data key that ${wrapper} holds wrapped; this server unwraps it at start-up. After a new generation, re-encrypt what is still under an older one.`
          : "Every secret at rest is encrypted under the server's master key. After rolling a new generation out (MASTER_KEY_VERSION), re-encrypt what is still under the old one."}
      </p>
      {status.isPending ? (
        <Spinner label="Loading…" />
      ) : status.isError ? (
        <ErrorLine error={status.error} />
      ) : (
        <>
          <dl>
            <Row label="Key custody">{wrapper ? <Badge tone="ok">{wrapper}</Badge> : "Environment (MASTER_KEY)"}</Row>
            <Row label="Current generation">{status.data.current_version}</Row>
            <Row label="Rows under older generations">{status.data.pending_rows === 0 ? <Badge tone="ok">None</Badge> : <Badge tone="accent">{status.data.pending_rows}</Badge>}</Row>
          </dl>
          {status.data.generations.length > 0 && (
            <ul aria-label="Master-key generations" className="mt-3 divide-y divide-line rounded-[var(--radius)] border border-line text-small">
              {status.data.generations.map((g) => (
                <li key={g.version} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
                  <span className="font-medium text-ink">Generation {g.version}</span>
                  <Badge tone={g.version === status.data.current_version ? "ok" : "neutral"}>{g.backend === "env" ? "environment" : g.backend}</Badge>
                  {!g.loaded && <Badge tone="danger">not readable on this server</Badge>}
                  {g.key_ref && <code className="min-w-0 break-all font-mono text-caption text-muted">{g.key_ref}</code>}
                  {g.created_at && <span className="text-muted">{formatDate("en", g.created_at)}</span>}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {generate.data && (
        <p role="status" className="mt-3 text-small text-muted">
          Generation {generate.data.version} created and current; re-encrypt the pending rows to move them onto it.
        </p>
      )}
      {rotate.data && (
        <p role="status" className="mt-3 text-small text-muted">
          Re-encrypted {Object.values(rotate.data.rewritten).reduce((a, b) => a + b, 0)} rows under generation {rotate.data.target_version}
          {Object.keys(rotate.data.failed).length ? `; ${Object.values(rotate.data.failed).reduce((a, b) => a + b, 0)} failed` : ""}.
        </p>
      )}
      <ErrorLine error={generate.error} />
      <ErrorLine error={rotate.error} />
    </Card>
  );
}
