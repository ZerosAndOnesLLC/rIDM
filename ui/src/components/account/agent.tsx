"use client";

import { Bot, Monitor, Smartphone, Tablet } from "lucide-react";
import { useI18n } from "@/i18n/provider";
import { parseUserAgent } from "@/lib/ua";

/** "Chrome on Linux", in the page's language; the raw string stays as the tooltip. */
export function AgentLabel({ ua }: { ua: string | null | undefined }) {
  const { t } = useI18n();
  const a = parseUserAgent(ua);
  const text = a.browser && a.os ? t("account.agent_on", { browser: a.browser, os: a.os }) : (a.browser ?? a.os ?? (ua ? ua.split(/[\s/]/)[0] : null) ?? t("account.agent_unknown"));
  return <span title={ua ?? undefined}>{text}</span>;
}

/** A phone, tablet, desktop or robot glyph for the kind of device. */
export function DeviceIcon({ ua }: { ua: string | null | undefined }) {
  const { device } = parseUserAgent(ua);
  const Icon = device === "phone" ? Smartphone : device === "tablet" ? Tablet : device === "bot" ? Bot : Monitor;
  return (
    <span aria-hidden className="flex size-[2.125rem] shrink-0 items-center justify-center rounded-[9px] bg-accent-soft text-accent-text">
      <Icon className="size-4" />
    </span>
  );
}
