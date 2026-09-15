"use client";

import { useI18n } from "@/i18n/provider";
import { ApiError } from "@/lib/api";
import type { FlowError } from "@/lib/flow";
import { toFlowError } from "@/lib/flow";

/** Human text for a failed request, in the page's language. */
export function useErrorText() {
  const { t } = useI18n();
  return (e: FlowError | unknown | null): string | null => {
    if (!e) return null;
    const err: FlowError = isFlowError(e) ? e : toFlowError(e);
    if (err.kind === "expired") return t("common.expired");
    if (err.kind === "network") return t("common.error_network");
    const a = err.error;
    if (a.status === 429) return t("common.rate_limited");
    switch (a.code) {
      case "invalid_credentials":
        return t("login.invalid_credentials");
      case "account_locked":
        return t("login.account_locked");
      case "invalid_code":
        return t("login.invalid_code");
      case "conflict":
        return t("register.email_taken");
    }
    const fields = a.fieldErrors();
    if (fields.captcha_token) return t("login.captcha_required");
    const first = Object.values(fields)[0];
    if (first) return first;
    return a.message || t("common.error_generic");
  };
}

function isFlowError(e: unknown): e is FlowError {
  return typeof e === "object" && e !== null && "kind" in e && !(e instanceof ApiError);
}
