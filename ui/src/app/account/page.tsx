"use client";

import { useI18n } from "@/i18n/provider";
import { Contact } from "@/components/account/contact";
import { Profile } from "@/components/account/profile";

/** The account console's first page: who the user is, and how to reach them. */
export default function Page() {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-[1.5rem] font-semibold leading-tight tracking-[-0.01em] text-ink">{t("account.profile")}</h1>
      <Profile />
      <Contact />
    </div>
  );
}
