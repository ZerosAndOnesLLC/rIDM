"use client";

import { useSearchParams } from "next/navigation";
import { ResourceServersPage } from "@/components/console/access/resource-servers";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <ResourceServersPage tenant={tenant} selected={sp.get("rs")} />;
}
