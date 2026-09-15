"use client";

import { ConfigPage } from "@/components/console/config";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Spinner label="Loading…" />;
  return <ConfigPage tenant={tenant} />;
}
