"use client";

import { ProvisioningPage } from "@/components/console/ops/provisioning";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Spinner label="Loading…" />;
  return <ProvisioningPage tenant={tenant} />;
}
