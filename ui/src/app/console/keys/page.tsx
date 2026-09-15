"use client";

import { KeysPage } from "@/components/console/ops/keys";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Spinner label="Loading…" />;
  return <KeysPage tenant={tenant} />;
}
