"use client";

import { Suspense, type ReactNode } from "react";
import { ConsoleShell } from "@/components/console/shell";
import { ConsoleProvider } from "@/lib/console/session";
import { ThemeProvider } from "@/lib/console/theme";

/**
 * Every `/console/...` page: session, theme, and the shell. Pages read the
 * current tenant from the query string, hence the Suspense boundary the
 * static export needs around `useSearchParams`.
 */
export default function ConsoleLayout({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider>
      <ConsoleProvider>
        <Suspense fallback={null}>
          <ConsoleShell>{children}</ConsoleShell>
        </Suspense>
      </ConsoleProvider>
    </ThemeProvider>
  );
}
