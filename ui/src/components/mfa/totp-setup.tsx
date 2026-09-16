"use client";

import { useI18n } from "@/i18n/provider";
import { Spinner } from "@/components/ui";
import type { TotpEnrolment } from "@/lib/types";

/** The QR code and manual key of a pending authenticator enrolment (a spinner until both exist). */
export function TotpSetup({ enrolment, qr }: { enrolment: TotpEnrolment | null; qr: string | null }) {
  const { t } = useI18n();
  if (!enrolment || !qr) return <Spinner label={t("common.loading")} />;
  return (
    <div className="flex flex-col items-center gap-3 rounded-[var(--radius)] border border-line bg-paper p-4">
      {/* eslint-disable-next-line @next/next/no-img-element -- data URL rendered client-side */}
      <img src={qr} width={192} height={192} alt={t("mfa.qr_alt", { account: enrolment.account })} className="rounded-md bg-white" />
      <p className="text-[0.8125rem] text-muted">{t("mfa.manual_key")}</p>
      <code data-testid="totp-secret" className="max-w-full break-all rounded-md bg-ground px-2 py-1 font-mono text-[0.875rem] text-ink select-all">
        {enrolment.secret}
      </code>
    </div>
  );
}
