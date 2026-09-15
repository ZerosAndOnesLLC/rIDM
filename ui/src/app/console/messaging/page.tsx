"use client";

import { useSearchParams } from "next/navigation";
import { MessagingPage } from "@/components/console/ops/messaging";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <MessagingPage tenant={tenant} tab={sp.get("tab")} />;
}
