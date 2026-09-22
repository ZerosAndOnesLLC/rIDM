"use client";

import { ClientCertificatesPage } from "@/components/console/ops/client-certificates";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Spinner label="Loading…" />;
  return <ClientCertificatesPage tenant={tenant} />;
}
