import type { NextConfig } from "next";

// Static export: the build writes plain HTML/JS/CSS to `out/`, which the API
// embeds (single-binary mode) or any static host serves. `trailingSlash` makes
// every page a directory index so `/login/` resolves on any file server.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  reactStrictMode: true,
  images: { unoptimized: true },
  env: {
    // Empty means "same origin" (embedded mode). Set at build time when the UI
    // is hosted separately from the API.
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "",
  },
  // `next dev` only (rewrites do not apply to a static export): proxy the API
  // so pages call it same-origin, exactly as in embedded mode, and session
  // cookies work without CORS. `API_PROXY=http://localhost:8090 npm run dev`.
  // The trailing-slash redirect would rewrite API paths, so it is off in that
  // mode; every in-app link already carries its slash.
  skipTrailingSlashRedirect: Boolean(process.env.API_PROXY),
  async rewrites() {
    const target = process.env.API_PROXY;
    if (!target) return [];
    return ["t", "healthz", "readyz", ".well-known"].map((p) => ({
      source: `/${p}/:path*`,
      destination: `${target}/${p}/:path*`,
    }));
  },
};

export default nextConfig;
