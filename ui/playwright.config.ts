import { defineConfig, devices } from "@playwright/test";

// End-to-end tests drive the real pages against a running API (see e2e/README.md).
// Locally, `next dev` is started here with the API proxied same-origin, as in
// embedded mode. CI sets E2E_UI_URL to the API itself, built with the
// `embedded-ui` feature, so the suite covers the static export that ships.
const UI_PORT = Number(process.env.E2E_UI_PORT ?? 3110);
const UI = process.env.E2E_UI_URL ?? `http://localhost:${UI_PORT}`;
const API = process.env.E2E_API_URL ?? "http://localhost:8090";

// The pages end users sign in with run on every engine people use: Safari
// (WebKit) and Firefox differ from Chromium in the places sign-in touches
// (cookies, autofill, focus, storage). The console, and the specs that need
// Chromium-only tooling (a virtual authenticator for passkeys, SPNEGO for
// Kerberos), stay on Chromium.
const CROSS_BROWSER =
  /\/(login|logout|mfa|mfa-otp|email-otp|magic-link|consent|register|recover|password-change|lockout|profile-terms|invite|account|account-profile)\.spec\.ts$/;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL: UI,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] }, testMatch: CROSS_BROWSER },
    { name: "firefox", use: { ...devices["Desktop Firefox"] }, testMatch: CROSS_BROWSER },
  ],
  webServer: process.env.E2E_UI_URL
    ? undefined
    : {
        command: `API_PROXY=${API} npx next dev -p ${UI_PORT}`,
        url: `${UI}/login/`,
        reuseExistingServer: true,
        timeout: 120_000,
        env: { API_PROXY: API },
      },
});
