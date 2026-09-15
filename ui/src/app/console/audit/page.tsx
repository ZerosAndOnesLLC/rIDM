"use client";

import { AuditPage } from "@/components/console/ops/audit";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Spinner label="Loading…" />;
  return <AuditPage tenant={tenant} />;
}
