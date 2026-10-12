import type { Metadata } from "next";
import type { ReactNode } from "react";
import { I18nProvider } from "@/i18n/provider";
import { ThemeProvider } from "@/lib/theme/provider";
import "./globals.css";

export const metadata: Metadata = {
  title: "rIDM",
  description: "Identity management",
};

// Restores the tenant's skin and the effective light/dark choice before the
// first paint: the tenant's cached policy (written by src/lib/theme/appearance.ts
// under the slug in the query string) decides whether the person's own choice
// applies. The attributes are set on <html> ahead of hydration, hence the
// suppression. Mirrors `effectiveTheme` in src/lib/theme/appearance.ts.
const THEME_BOOT = `try{var d=document.documentElement,q=new URLSearchParams(location.search).get("tenant"),a=q?JSON.parse(localStorage.getItem("ridm.appearance:"+q)||"null"):null,t=localStorage.getItem("ridm.theme"),m=(a&&(a.mode==="light"||a.mode==="dark"))?a.mode:"system",w=!a||a.allow!==false,u=(t==="light"||t==="dark")?t:"system",e=(w&&u!=="system")?u:m;if(a&&a.skin)d.dataset.skin=a.skin;if(e!=="system")d.dataset.theme=e}catch(e){}`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
        <link rel="preload" href="/fonts/hanken-grotesk-latin.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
        <link rel="preload" href="/fonts/bricolage-grotesque-latin.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
      </head>
      <body className="min-h-screen antialiased">
        <ThemeProvider>
          <I18nProvider>{children}</I18nProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
