"use client";

import { Skeleton } from "@/components/base/skeleton";
import { AuditPage } from "@/components/console/ops/audit";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <AuditPage tenant={tenant} />;
}
