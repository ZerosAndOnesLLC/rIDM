"use client";

import { useSearchParams } from "next/navigation";
import { OrganizationsPage } from "@/components/console/access/organizations";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <OrganizationsPage tenant={tenant} selected={sp.get("org")} />;
}
