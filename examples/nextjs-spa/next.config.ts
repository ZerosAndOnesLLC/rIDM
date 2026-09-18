import type { NextConfig } from "next";

// A static export: `next build` writes plain HTML/JS/CSS to `out/`, which any
// static host serves. A public OAuth client needs no server of its own — that
// is the whole point of PKCE.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  reactStrictMode: true,
  images: { unoptimized: true },
  env: {
    NEXT_PUBLIC_RIDM_ISSUER:
      process.env.NEXT_PUBLIC_RIDM_ISSUER ?? "http://localhost:8090/t/demo",
    NEXT_PUBLIC_CLIENT_ID: process.env.NEXT_PUBLIC_CLIENT_ID ?? "orders-spa",
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8081",
    NEXT_PUBLIC_API_AUDIENCE:
      process.env.NEXT_PUBLIC_API_AUDIENCE ?? "https://orders.example",
  },
};

export default nextConfig;
