"use client";

import { useSearchParams } from "next/navigation";
import { MappersPage } from "@/components/console/access/mappers";
import { Spinner } from "@/components/ui";
import { useConsoleTenant } from "@/lib/console/tenant";

export default function Page() {
  const tenant = useConsoleTenant();
  const sp = useSearchParams();
  if (!tenant) return <Spinner label="Loading…" />;
  return <MappersPage tenant={tenant} selected={sp.get("mapper")} />;
}
