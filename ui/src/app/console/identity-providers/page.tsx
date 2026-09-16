"use client";

import { useSearchParams } from "next/navigation";
import { IdentityProvidersPage } from "@/components/console/ops/identity-providers";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <IdentityProvidersPage tenant={tenant} selected={sp.get("idp")} />;
}
