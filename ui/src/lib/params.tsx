"use client";

import { Suspense, useCallback, useMemo, type ReactNode } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

/** Query parameters every page is driven by. */
export interface PageParams {
  tenant: string | null;
  flow: string | null;
  get: (name: string) => string | null;
}

export function usePageParams(): PageParams {
  const sp = useSearchParams();
  return {
    tenant: sp.get("tenant"),
    flow: sp.get("flow"),
    get: (name) => sp.get(name),
  };
}

/** `useSearchParams` needs a Suspense boundary in a static export. */
export function WithParams({ children }: { children: ReactNode }) {
  return <Suspense fallback={null}>{children}</Suspense>;
}

export function navigate(url: string) {
  window.location.assign(url);
}

/**
 * A list's filters in the URL (`?q=ada&status=locked&sort=username`), so a
 * link, a reload and the back button land on the same view. `set` replaces
 * the history entry and leaves `tenant`, `view` and `tab` alone; an empty
 * value removes its key.
 */
export function useQueryParams(): { get: (name: string) => string; set: (patch: Record<string, string | null | undefined>) => void } {
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const get = useCallback((name: string) => sp.get(name) ?? "", [sp]);
  const set = useCallback(
    (patch: Record<string, string | null | undefined>) => {
      const q = new URLSearchParams(sp.toString());
      let changed = false;
      for (const [k, v] of Object.entries(patch)) {
        const next = v ?? "";
        if ((q.get(k) ?? "") === next) continue;
        changed = true;
        if (next === "") q.delete(k);
        else q.set(k, next);
      }
      if (changed) router.replace(`${pathname}?${q}`, { scroll: false });
    },
    [sp, router, pathname],
  );
  return useMemo(() => ({ get, set }), [get, set]);
}
