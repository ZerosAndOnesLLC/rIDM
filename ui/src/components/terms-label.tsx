"use client";

import { useI18n } from "@/i18n/provider";

/** "I agree to the {terms} and {privacy}" with the links substituted. */
export function TermsLabel({ terms, privacy }: { terms: string | null; privacy: string | null }) {
  const { t } = useI18n();
  const link = (href: string | null, label: string) =>
    href ? (
      <a href={href} target="_blank" rel="noreferrer" className="text-link underline underline-offset-4">
        {label}
      </a>
    ) : (
      <span>{label}</span>
    );
  const parts = t("register.terms_accept").split(/(\{terms\}|\{privacy\})/);
  return (
    <span>
      {parts.map((p, i) =>
        p === "{terms}" ? <span key={i}>{link(terms, t("register.terms"))}</span> : p === "{privacy}" ? <span key={i}>{link(privacy, t("register.privacy"))}</span> : <span key={i}>{p}</span>,
      )}
    </span>
  );
}
