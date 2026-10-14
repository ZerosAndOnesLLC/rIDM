"use client";

import { useI18n } from "@/i18n/provider";
import { Devices } from "@/components/account/devices";
import { Identities } from "@/components/account/identities";
import { Password } from "@/components/account/password";
import { SecurityScore } from "@/components/account/score";
import { Security } from "@/components/account/security";
import { Sessions } from "@/components/account/sessions";
import { Tokens } from "@/components/account/tokens";

/** Password, second step, trusted devices and where the user is signed in. */
export default function Page() {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-2xl font-semibold leading-tight tracking-[-0.01em] text-ink">{t("account.security")}</h1>
      <SecurityScore />
      <Password />
      <Security />
      <Identities />
      <Devices />
      <Sessions />
      <Tokens />
    </div>
  );
}
