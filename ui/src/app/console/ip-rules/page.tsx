"use client";

import { Skeleton } from "@/components/base/skeleton";
import { IpRulesPage } from "@/components/console/ops/ip-rules";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <IpRulesPage tenant={tenant} />;
}
