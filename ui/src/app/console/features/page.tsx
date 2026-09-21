"use client";

import { FeatureFlagsPage } from "@/components/console/features/page";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Spinner label="Loading…" />;
  return <FeatureFlagsPage tenant={tenant} />;
}
