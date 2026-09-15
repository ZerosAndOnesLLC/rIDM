"use client";

import { IpRulesPage } from "@/components/console/ops/ip-rules";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Spinner label="Loading…" />;
  return <IpRulesPage tenant={tenant} />;
}
