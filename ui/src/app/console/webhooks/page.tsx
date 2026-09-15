"use client";

import { useSearchParams } from "next/navigation";
import { WebhooksPage } from "@/components/console/ops/webhooks";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <WebhooksPage tenant={tenant} selected={sp.get("webhook")} />;
}
