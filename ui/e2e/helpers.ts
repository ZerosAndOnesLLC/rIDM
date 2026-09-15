import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

export const API = process.env.E2E_API_URL ?? "http://localhost:8090";
export const MAILPIT = process.env.E2E_MAILPIT_URL ?? "http://localhost:8026";
export const TENANT = process.env.E2E_TENANT ?? "master";
export const DATABASE_URL =
  process.env.E2E_DATABASE_URL ?? "postgres://ridm_migrator:ridm_migrator@localhost:5440/ridm";
export const REDIS_URL = process.env.E2E_REDIS_URL ?? "redis://localhost:6390";
export const STATE_FILE = join(__dirname, ".state.json");
export const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

export interface State {
  ui: string;
  client_id: string;
  email: string;
  password: string;
}

export function loadState(): State {
  return JSON.parse(readFileSync(STATE_FILE, "utf8")) as State;
}
export function saveState(s: State) {
  writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
}

/** Tenant-scoped API path, same-origin through the dev proxy. */
export function t(path: string): string {
  return `/t/${TENANT}${path}`;
}

export function authorizeUrl(state: State, extra: Record<string, string> = {}): string {
  const q = new URLSearchParams({
    response_type: "code",
    client_id: state.client_id,
    redirect_uri: `${state.ui}/callback/`,
    scope: "openid profile",
    state: "st",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    ...extra,
  });
  return `${t("/authorize")}?${q}`;
}

/** Run one SQL statement with psql. */
export function sql(statement: string): string {
  return execFileSync("psql", [DATABASE_URL, "-tA", "-v", "ON_ERROR_STOP=1", "-c", statement], {
    encoding: "utf8",
  }).trim();
}

/** Drop cached tenant documents so settings written by SQL take effect. */
export function clearTenantCache() {
  try {
    const keys = execFileSync("redis-cli", ["-u", REDIS_URL, "--scan", "--pattern", "ridm:*tenant*"], {
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean);
    if (keys.length) execFileSync("redis-cli", ["-u", REDIS_URL, "del", ...keys]);
  } catch (e) {
    console.warn("redis-cli unavailable; tenant cache not cleared:", String(e).split("\n")[0]);
  }
}

interface MailpitMessage {
  ID: string;
  Subject: string;
  To: { Address: string }[];
  Created: string;
}

export const mailpit = {
  async clear() {
    await fetch(`${MAILPIT}/api/v1/messages`, { method: "DELETE" });
  },
  /** Newest message to `to`, waiting up to `timeoutMs`. Returns its text body. */
  async waitFor(to: string, timeoutMs = 15_000): Promise<{ subject: string; text: string; links: string[] }> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const res = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}&limit=1`);
      const body = (await res.json()) as { messages: MailpitMessage[] };
      const m = body.messages?.[0];
      if (m) {
        const full = (await (await fetch(`${MAILPIT}/api/v1/message/${m.ID}`)).json()) as { Text: string; Subject: string };
        await fetch(`${MAILPIT}/api/v1/messages`, {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ IDs: [m.ID] }),
        });
        const links = [...full.Text.matchAll(/https?:\/\/\S+/g)].map((x) => x[0]);
        return { subject: full.Subject, text: full.Text, links };
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    throw new Error(`no mail for ${to} within ${timeoutMs}ms`);
  },
};

/** The page's own alert (Next's route announcer also carries role=alert). */
export function alertOf(page: Page) {
  return page.locator("[role=alert]:not(#__next-route-announcer__)");
}

/** Fail on serious or critical accessibility violations on the current page. */
export async function expectAccessible(page: Page) {
  // The card fades in; sampling colours mid-animation gives false contrast failures.
  await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished.catch(() => undefined))));
  const results = await new AxeBuilder({ page }).analyze();
  const bad = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad, JSON.stringify(bad, null, 2)).toEqual([]);
}

/** After authentication: approve consent if asked, then expect the code on the callback. */
export async function finishAuthorization(page: Page): Promise<URL> {
  await page.waitForURL(/\/(consent|callback)\//, { timeout: 15_000 });
  if (page.url().includes("/consent/")) {
    await expectAccessible(page);
    await page.getByRole("button", { name: "Allow" }).click();
    await page.waitForURL(/\/callback\//, { timeout: 15_000 });
  }
  const url = new URL(page.url());
  expect(url.searchParams.get("code")).toBeTruthy();
  expect(url.searchParams.get("state")).toBe("st");
  return url;
}

export async function loginWithPassword(page: Page, state: State, extra: Record<string, string> = {}) {
  await page.goto(authorizeUrl(state, { prompt: "login", ...extra }));
  await page.waitForURL(/\/login\//);
  await page.getByLabel("Email or username").fill(state.email);
  await page.getByLabel("Password", { exact: true }).fill(state.password);
  await page.getByRole("button", { name: "Continue" }).click();
}
