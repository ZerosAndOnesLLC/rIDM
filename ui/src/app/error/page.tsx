"use client";

import { useI18n } from "@/i18n/provider";
import { AuthShell } from "@/components/shell";
import { Alert, Title } from "@/components/ui";
import { usePageParams, WithParams } from "@/lib/params";

export default function Page() {
  return (
    <WithParams>
      <ErrorPage />
    </WithParams>
  );
}

/** Terminal errors the API could not send back to the application. */
function ErrorPage() {
  const p = usePageParams();
  const { t } = useI18n();
  const code = p.get("error");
  const description = p.get("error_description");
  return (
    <AuthShell slug={p.tenant}>
      <Title sub={t("error.description")}>{t("error.title")}</Title>
      <Alert tone="error">
        {description ?? t("common.error_generic")}
        {code && <span className="mt-1 block font-mono text-[0.8125rem]">{code}</span>}
      </Alert>
    </AuthShell>
  );
}
