"use client";

import { Suspense, type ReactNode } from "react";
import { useSearchParams } from "next/navigation";

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
