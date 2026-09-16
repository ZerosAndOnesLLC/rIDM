"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert, Button, Checkbox, TextField } from "@/components/ui";
import { Badge, Button as CButton, Card, Modal } from "@/components/console/ui";
import { Secret } from "@/components/console/clients/reveal";
import { needsReauth, useAccount } from "@/lib/account/session";
import type { Schemas } from "@api/client";
import { useProblemText, useSecurityChange } from "./security";

type Token = Schemas["PersonalAccessToken"];

/** Long-lived bearer tokens for scripts and integrations, scoped to a subset of what the user may do. */
export function Tokens() {
  const { client, slug } = useAccount();
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const { reauth } = useSecurityChange();
  const problemText = useProblemText();
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<Token | null>(null);
  const [minted, setMinted] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const tokens = useQuery({
    queryKey: ["account", "tokens", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/tokens", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["account", "tokens", slug] });
  const fail = (e: unknown) => {
    if (needsReauth(e)) void reauth();
    else setError(problemText(e));
  };
  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await client.DELETE("/t/{slug}/account/tokens/{token_id}", { params: { path: { slug, token_id: id } } });
      if (error) throw error;
    },
    onSuccess: () => {
      setRevoking(null);
      refresh();
    },
    onError: (e: unknown) => {
      setRevoking(null);
      fail(e);
    },
  });
  const when = (iso: string | null | undefined) => (iso ? new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(new Date(iso)) : null);
  const d = tokens.data;
  if (d && !d.enabled && d.tokens.length === 0) return null;
  const live = (d?.tokens ?? []).filter((k) => !k.revoked_at);

  return (
    <>
      <Card
        title={t("account.tokens_title")}
        actions={
          d?.enabled ? (
            <CButton variant={live.length === 0 ? "primary" : "secondary"} onClick={() => setCreating(true)}>
              {t("account.tokens_new")}
            </CButton>
          ) : undefined
        }
      >
        <p className="text-[0.875rem] text-muted">{t("account.tokens_description")}</p>
        {error && (
          <div className="mt-3">
            <Alert tone="error">{error}</Alert>
          </div>
        )}
        {tokens.isError && <Alert tone="error">{t("account.error_generic")}</Alert>}
        {d && live.length === 0 && <p className="mt-3 text-[0.875rem] text-ink">{t("account.tokens_none")}</p>}
        {live.length > 0 && (
          <ul aria-label={t("account.tokens_title")} className="mt-3 divide-y divide-line">
            {live.map((k) => (
              <li key={k.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2 text-[0.9375rem] font-medium text-ink">
                    <span>{k.name}</span>
                    {k.scopes.map((s) => (
                      <Badge key={s}>{s}</Badge>
                    ))}
                  </p>
                  <p className="text-[0.8125rem] text-muted">
                    {t("account.token_created", { when: when(k.created_at) ?? "" })}
                    {k.expires_at ? ` · ${t("account.token_expires", { when: when(k.expires_at) ?? "" })}` : ` · ${t("account.token_never_expires")}`}
                    {k.last_used_at ? ` · ${t("account.token_used", { when: when(k.last_used_at) ?? "" })}` : ""}
                  </p>
                </div>
                <CButton variant="secondary" onClick={() => setRevoking(k)}>
                  {t("account.token_revoke")}
                </CButton>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Modal open={creating} onOpenChange={setCreating} title={t("account.tokens_new")}>
        {creating && d && (
          <CreateToken
            scopes={d.available_scopes}
            maxDays={d.max_days}
            onDone={(secret) => {
              setCreating(false);
              refresh();
              setMinted(secret);
            }}
            onReauth={() => void reauth()}
          />
        )}
      </Modal>

      <Modal open={minted !== null} onOpenChange={(o) => !o && setMinted(null)} title={t("account.token_minted_title")}>
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <p className="text-[0.9375rem] text-ink">{t("account.token_minted_hint")}</p>
          {minted && <Secret label={t("account.token_label")} value={minted} />}
          <Button type="button" onClick={() => setMinted(null)}>
            {t("account.token_saved")}
          </Button>
        </div>
      </Modal>

      <Modal open={revoking !== null} onOpenChange={(o) => !o && setRevoking(null)} title={t("account.token_revoke_title", { name: revoking?.name ?? "" })}>
        <div className="flex flex-col gap-4 px-5 pb-5 pt-3">
          <p className="text-[0.9375rem] text-ink">{t("account.token_revoke_hint")}</p>
          <div className="flex justify-end gap-2">
            <CButton variant="secondary" onClick={() => setRevoking(null)}>
              {t("common.cancel")}
            </CButton>
            <CButton variant="danger" onClick={() => revoking && revoke.mutate(revoking.id)} disabled={revoke.isPending}>
              {t("account.token_revoke")}
            </CButton>
          </div>
        </div>
      </Modal>
    </>
  );
}

function CreateToken({ scopes, maxDays, onDone, onReauth }: { scopes: string[]; maxDays: number; onDone: (secret: string) => void; onReauth: () => void }) {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const problemText = useProblemText();
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState<string[]>(["account"]);
  const [days, setDays] = useState(maxDays > 0 ? String(Math.min(90, maxDays)) : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toggle = (s: string, on: boolean) => setChosen((c) => (on ? [...c, s] : c.filter((x) => x !== s)));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { data, error } = await client.POST("/t/{slug}/account/tokens", {
        params: { path: { slug } },
        body: { name: name.trim(), scopes: chosen, expires_in_days: days.trim() ? Number(days) : null },
      });
      if (error) throw error;
      onDone(data.token);
    } catch (err) {
      if (needsReauth(err)) onReauth();
      else setError(problemText(err));
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-4 overflow-y-auto px-5 pb-5 pt-3" noValidate>
      <p className="text-[0.875rem] text-muted">{t("account.tokens_new_hint")}</p>
      {error && <Alert tone="error">{error}</Alert>}
      <TextField label={t("account.token_name")} value={name} onChange={(e) => setName(e.target.value)} maxLength={100} autoComplete="off" autoFocus required placeholder="CI script" />
      <fieldset className="flex flex-col gap-2">
        <legend className="text-[0.8125rem] font-medium text-ink">{t("account.token_scopes")}</legend>
        <p className="text-[0.8125rem] text-muted">{t("account.token_scopes_hint")}</p>
        {scopes.map((s) => (
          <Checkbox key={s} label={s === "account" ? t("account.token_scope_account") : s} checked={chosen.includes(s)} onChange={(e) => toggle(s, e.target.checked)} />
        ))}
      </fieldset>
      <TextField
        label={t("account.token_expiry")}
        type="number"
        inputMode="numeric"
        min={1}
        max={maxDays > 0 ? maxDays : undefined}
        value={days}
        onChange={(e) => setDays(e.target.value)}
        hint={maxDays > 0 ? t("account.token_expiry_max", { count: maxDays }) : t("account.token_expiry_optional")}
      />
      <Button type="submit" busy={busy} disabled={!name.trim() || chosen.length === 0}>
        {t("account.token_create")}
      </Button>
    </form>
  );
}
