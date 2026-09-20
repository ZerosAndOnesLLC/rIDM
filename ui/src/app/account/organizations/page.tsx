"use client";

import { useI18n } from "@/i18n/provider";
import { Organizations } from "@/components/account/organizations";

/** The organizations this account belongs to. */
export default function Page() {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-[1.5rem] font-semibold leading-tight tracking-[-0.01em] text-ink">{t("account.orgs")}</h1>
      <Organizations />
    </div>
  );
}
