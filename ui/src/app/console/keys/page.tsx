"use client";

import { Skeleton } from "@/components/base/skeleton";
import { KeysPage } from "@/components/console/ops/keys";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <KeysPage tenant={tenant} />;
}
