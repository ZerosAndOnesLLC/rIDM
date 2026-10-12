"use client";

import { Suspense, type ReactNode } from "react";
import { ToastProvider } from "@/components/base/toast";
import { AccountShell } from "@/components/account/shell";
import { AccountProvider } from "@/lib/account/session";

/** Every `/account/...` page: the session, toasts and the frame around the page. */
export default function AccountLayout({ children }: { children: ReactNode }) {
  return (
    <AccountProvider>
      <ToastProvider>
        <Suspense fallback={null}>
          <AccountShell>{children}</AccountShell>
        </Suspense>
      </ToastProvider>
    </AccountProvider>
  );
}
