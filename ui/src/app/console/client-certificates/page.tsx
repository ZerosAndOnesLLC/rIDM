"use client";

import { Skeleton } from "@/components/base/skeleton";
import { ClientCertificatesPage } from "@/components/console/ops/client-certificates";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <ClientCertificatesPage tenant={tenant} />;
}
