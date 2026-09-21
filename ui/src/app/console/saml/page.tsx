"use client";

import { useSearchParams } from "next/navigation";
import { SamlPage } from "@/components/console/ops/saml";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <SamlPage tenant={tenant} selected={sp.get("sp")} />;
}
