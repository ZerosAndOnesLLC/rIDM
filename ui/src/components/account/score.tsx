"use client";

import { useQuery } from "@tanstack/react-query";
import { useI18n } from "@/i18n/provider";
import { useAccount } from "@/lib/account/session";
import { useSecurityChange } from "./security";

/**
 * How well the account is protected, as one number with the next step to
 * take. The score adds up what the security page shows below it: a
 * password (30), the strongest second step (passkey 40, authenticator app
 * 35, codes 25), recovery codes (10), a verified email address (10) and a
 * second kind of second step (15). The card never blocks the page: until
 * the two status calls answer it simply is not there.
 */
export function SecurityScore() {
  const { client, slug, me } = useAccount();
  const { t } = useI18n();
  const { status } = useSecurityChange();
  const password = useQuery({
    queryKey: ["account", "password", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/password", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
  if (!status.data || !password.data) return null;
  const factors = status.data.factors;
  const kinds = new Set(factors.map((f) => f.kind));
  const hasPassword = password.data.enabled && password.data.set;
  const strongest = kinds.has("webauthn") ? 40 : kinds.has("totp") ? 35 : kinds.size > 0 ? 25 : 0;
  let score = 0;
  if (hasPassword) score += 30;
  score += strongest;
  if (factors.length > 0 && status.data.recovery_codes > 0) score += 10;
  if (me?.email_verified) score += 10;
  if (kinds.size > 1) score += 15;
  score = Math.min(100, score);
  const hint =
    !hasPassword && factors.length === 0
      ? t("account.score_hint_none")
      : factors.length === 0
        ? t("account.score_hint_second")
        : status.data.recovery_codes === 0
          ? t("account.score_hint_codes")
          : me?.email && !me.email_verified
            ? t("account.score_hint_email")
            : kinds.size < 2
              ? t("account.score_hint_backup")
              : t("account.score_hint_done");
  const title = score >= 70 ? t("account.score_good") : score >= 40 ? t("account.score_ok") : t("account.score_bad");
  const ring = score >= 70 ? "var(--accent-solid)" : score >= 40 ? "var(--warn)" : "var(--danger)";
  return (
    <section aria-labelledby="security-score" className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-4 rounded-[var(--radius-lg)] border border-accent-border bg-[linear-gradient(135deg,var(--accent-soft-2),var(--paper))] px-4 py-3.5">
      <div role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100} aria-label={t("account.score_title")} className="flex size-14 items-center justify-center rounded-full" style={{ background: `conic-gradient(${ring} 0 ${score}%, var(--line) ${score}% 100%)` }}>
        <span className="font-display flex size-11 items-center justify-center rounded-full bg-paper text-lead font-semibold text-ink">{score}</span>
      </div>
      <div className="min-w-0">
        <h2 id="security-score" className="text-md font-semibold text-ink">
          {title}
        </h2>
        <p className="text-small text-muted">
          {hint} <span className="font-mono text-caption">{t("account.score_of", { score })}</span>
        </p>
      </div>
    </section>
  );
}
