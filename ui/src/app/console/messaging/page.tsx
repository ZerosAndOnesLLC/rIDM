"use client";

import { Skeleton } from "@/components/base/skeleton";
import { useSearchParams } from "next/navigation";
import { MessagingPage } from "@/components/console/ops/messaging";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <MessagingPage tenant={tenant} tab={sp.get("tab")} />;
}
