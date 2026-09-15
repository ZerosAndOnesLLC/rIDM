import { defineConfig, devices } from "@playwright/test";

// End-to-end tests drive the real pages against a running API (see e2e/README.md).
// `next dev` is started here with the API proxied same-origin, exactly as in
// embedded mode; Phase 11 switches this to the static export served by the API.
const UI_PORT = Number(process.env.E2E_UI_PORT ?? 3110);
const UI = process.env.E2E_UI_URL ?? `http://localhost:${UI_PORT}`;
const API = process.env.E2E_API_URL ?? "http://localhost:8090";

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
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
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
