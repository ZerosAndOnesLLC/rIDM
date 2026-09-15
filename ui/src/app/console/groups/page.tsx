"use client";

import { useSearchParams } from "next/navigation";
import { GroupsPage } from "@/components/console/access/groups";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <GroupsPage tenant={tenant} selected={sp.get("group")} />;
}
