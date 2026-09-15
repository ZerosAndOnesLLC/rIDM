"use client";

import { useSearchParams } from "next/navigation";
import { useConsole } from "./session";

/**
 * The tenant the console is looking at: `?tenant=` when present, otherwise
 * the administrator's own. Global administrators switch it; everyone else is
 * pinned to theirs (the API refuses anything else anyway).
 */
export function useConsoleTenant(): string | null {
  const sp = useSearchParams();
  const { me } = useConsole();
  const requested = sp.get("tenant");
  if (!me) return requested;
  if (me.scope === "global" && requested) return requested;
  return me.tenant_slug;
}
