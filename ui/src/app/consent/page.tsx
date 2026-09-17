"use client";

import { useState } from "react";
import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { useErrorText } from "@/components/errors";
import { Alert, Button, Checkbox, Spinner, Title } from "@/components/ui";
import { useFlow } from "@/lib/flow";
import { usePageParams, WithParams } from "@/lib/params";

const ACCEPTS = ["consent", "done"] as const;

export default function Page() {
  return (
    <WithParams>
      <ConsentPage />
    </WithParams>
  );
}

function ConsentPage() {
  const p = usePageParams();
  const f = useFlow(p.tenant, p.flow, ACCEPTS);
  const { t } = useI18n();
  const errorText = useErrorText();
  const [declined, setDeclined] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const flow = f.flow;

  const decide = async (approve: boolean) => {
    if (!flow) return;
    setBusy(approve ? "approve" : "deny");
    setError(null);
    try {
      const scopes = flow.pending_scopes.map((s) => s.name).filter((n) => n === "openid" || !declined.has(n));
      await f.post("consent", approve ? { approve: true, scopes } : { approve: false });
    } catch (e) {
      setError(errorText(e));
      setBusy(null);
    }
  };

  return (
    <AuthShell slug={p.tenant} locale={flow?.locale} locales={flow?.locales}>
      {f.loading || f.redirected || !flow ? (
        f.error ? <Alert tone="error">{errorText(f.error)}</Alert> : <Spinner label={t("common.loading")} />
      ) : (
        <div className="flex flex-col gap-5">
          <Title sub={t("consent.description", { client: flow.client.name })}>{t("consent.title")}</Title>
          {flow.user && <p className="-mt-3 text-[0.875rem] text-muted">{t("consent.signed_in_as", { username: flow.user.username })}</p>}
          {error && <Alert tone="error">{error}</Alert>}
          <ul className="flex flex-col divide-y divide-line rounded-[var(--radius)] border border-line">
            {flow.pending_scopes.map((s) => (
              <li key={s.name} className="px-3.5 py-3">
                <Checkbox
                  checked={s.name === "openid" || !declined.has(s.name)}
                  disabled={s.name === "openid"}
                  onChange={(e) =>
                    setDeclined((d) => {
                      const n = new Set(d);
                      if (e.target.checked) n.delete(s.name);
                      else n.add(s.name);
                      return n;
                    })
                  }
                  label={
                    <span className="flex flex-col">
                      <span className="font-medium">{s.description ?? s.name}</span>
                      {s.description && <span className="text-[0.8125rem] text-muted">{s.name}</span>}
                    </span>
                  }
                />
              </li>
            ))}
          </ul>
          <div className="flex flex-col gap-2 sm:flex-row-reverse">
            <Button id="consent-approve" type="button" busy={busy === "approve"} disabled={busy !== null} onClick={() => void decide(true)}>
              {t("consent.approve")}
            </Button>
            <Button type="button" variant="secondary" busy={busy === "deny"} disabled={busy !== null} onClick={() => void decide(false)}>
              {t("consent.deny")}
            </Button>
          </div>
          {(flow.client.tos_uri || flow.client.policy_uri) && (
            <p className="text-center text-[0.8125rem] text-muted">
              {flow.client.tos_uri && (
                <a href={flow.client.tos_uri} target="_blank" rel="noreferrer" className="hover:underline underline-offset-4">
                  {t("register.terms")}
                </a>
              )}
              {flow.client.tos_uri && flow.client.policy_uri && " · "}
              {flow.client.policy_uri && (
                <a href={flow.client.policy_uri} target="_blank" rel="noreferrer" className="hover:underline underline-offset-4">
                  {t("register.privacy")}
                </a>
              )}
            </p>
          )}
        </div>
      )}
    </AuthShell>
  );
}
