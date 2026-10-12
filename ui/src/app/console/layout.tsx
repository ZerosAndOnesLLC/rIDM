"use client";

import { Suspense, type ReactNode } from "react";
import { ToastProvider } from "@/components/base/toast";
import { ConsoleShell } from "@/components/console/shell";
import { ConsoleProvider } from "@/lib/console/session";

/**
 * Every `/console/...` page: session, toasts and the shell (the theme provider
 * sits in the root layout). Pages read the
 * current tenant from the query string, hence the Suspense boundary the
 * static export needs around `useSearchParams`.
 */
export default function ConsoleLayout({ children }: { children: ReactNode }) {
  return (
    <ConsoleProvider>
      <ToastProvider>
        <Suspense fallback={null}>
          <ConsoleShell>{children}</ConsoleShell>
        </Suspense>
      </ToastProvider>
    </ConsoleProvider>
  );
}
