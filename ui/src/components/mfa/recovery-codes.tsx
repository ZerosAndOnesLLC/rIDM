"use client";

import { useState } from "react";
import { useI18n } from "@/i18n/provider";
import { Button, Title } from "@/components/ui";

/** The recovery codes, shown once, with copy and download; `onDone` moves on. */
export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const text = codes.join("\n");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  const href = `data:text/plain;charset=utf-8,${encodeURIComponent(`${text}\n`)}`;
  return (
    <div className="flex flex-col gap-5">
      <Title sub={t("mfa.codes_description")}>{t("mfa.codes_title")}</Title>
      <ul aria-label={t("mfa.codes_title")} className="grid grid-cols-2 gap-x-6 gap-y-2 rounded-[var(--radius)] border border-line bg-paper p-4 font-mono text-[0.9375rem] text-ink">
        {codes.map((c) => (
          <li key={c} className="select-all">
            {c}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="secondary" className="flex-1" onClick={() => void copy()} aria-live="polite">
          {copied ? t("mfa.codes_copied") : t("mfa.codes_copy")}
        </Button>
        <a
          href={href}
          download="recovery-codes.txt"
          className="inline-flex min-h-11 flex-1 items-center justify-center rounded-[var(--radius)] border border-line px-4 text-[0.9375rem] font-medium text-ink hover:bg-ground"
        >
          {t("mfa.codes_download")}
        </a>
      </div>
      <Button type="button" onClick={onDone}>
        {t("mfa.codes_saved")}
      </Button>
    </div>
  );
}
