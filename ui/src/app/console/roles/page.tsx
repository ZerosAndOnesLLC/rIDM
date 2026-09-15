"use client";

import { useSearchParams } from "next/navigation";
import { RolesPage } from "@/components/console/access/roles";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <RolesPage tenant={tenant} selected={sp.get("role")} />;
}
