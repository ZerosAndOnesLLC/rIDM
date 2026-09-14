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
};

export default nextConfig;
