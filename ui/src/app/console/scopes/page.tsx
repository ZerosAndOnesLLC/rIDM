"use client";

import { useSearchParams } from "next/navigation";
import { ScopesPage } from "@/components/console/access/scopes";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <ScopesPage tenant={tenant} selected={sp.get("scope")} />;
}
