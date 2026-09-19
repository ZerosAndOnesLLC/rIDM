import type { NextConfig } from "next";

// Static export: the build writes plain HTML/JS/CSS to `out/`, which any
// static host serves, and which the API embeds with its `embedded-ui` feature
// (single-binary mode). `trailingSlash` makes
// every page a directory index so `/login/` resolves on any file server.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  reactStrictMode: true,
  images: { unoptimized: true },
  env: {
    // Empty means "same origin" (the UI and the API behind one host). Set at
    // build time when the UI is hosted on a different origin from the API.
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "",
  },
  // `next dev` only (rewrites do not apply to a static export): proxy the API
  // so pages call it same-origin, as in a same-origin deployment, and session
  // cookies work without CORS. `API_PROXY=http://localhost:8090 npm run dev`.
  // The trailing-slash redirect would rewrite API paths, so it is off in that
  // mode; every in-app link already carries its slash. The admin console lives
  // under `/console/` because `/admin/*` is the API.
  skipTrailingSlashRedirect: Boolean(process.env.API_PROXY),
  async rewrites() {
    const target = process.env.API_PROXY;
    if (!target) return [];
    return [
      ...["t", "admin", "healthz", "readyz", ".well-known"].map((p) => ({
        source: `/${p}/:path*`,
        destination: `${target}/${p}/:path*`,
      })),
      { source: "/openapi.json", destination: `${target}/openapi.json` },
    ];
  },
};

export default nextConfig;
