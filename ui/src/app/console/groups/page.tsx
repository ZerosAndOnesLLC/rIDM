"use client";

import { Skeleton } from "@/components/base/skeleton";
import { useSearchParams } from "next/navigation";
import { GroupsPage } from "@/components/console/access/groups";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <GroupsPage tenant={tenant} selected={sp.get("group")} />;
}
