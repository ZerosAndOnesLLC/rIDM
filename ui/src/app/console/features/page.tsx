"use client";

import { Skeleton } from "@/components/base/skeleton";
import { FeatureFlagsPage } from "@/components/console/features/page";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <FeatureFlagsPage tenant={tenant} />;
}
