"use client";

import { Skeleton } from "@/components/base/skeleton";
import { useSearchParams } from "next/navigation";
import { IdentityProvidersPage } from "@/components/console/ops/identity-providers";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Skeleton shape="lines" count={4} label="Loading…" />;
  return <IdentityProvidersPage tenant={tenant} selected={sp.get("idp")} />;
}
