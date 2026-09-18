import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Orders (rIDM SPA example)",
  description: "A single-page app signing users in with rIDM",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
