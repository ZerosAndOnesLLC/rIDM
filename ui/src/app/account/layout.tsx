"use client";

import { Suspense, type ReactNode } from "react";
import { AccountShell } from "@/components/account/shell";
import { AccountProvider } from "@/lib/account/session";

/** Every `/account/...` page: the session and the frame around the page. */
export default function AccountLayout({ children }: { children: ReactNode }) {
  return (
    <AccountProvider>
      <Suspense fallback={null}>
        <AccountShell>{children}</AccountShell>
      </Suspense>
    </AccountProvider>
  );
}
