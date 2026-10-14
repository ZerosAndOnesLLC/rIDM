// Regenerates the website's screenshots (site/assets/screens/*.png) from the
// running dev stack at a fixed viewport, so they stay comparable between
// releases. Needs the API on :8090 and the UI on :3110 (`make api`, `make ui`),
// the acme tenant seeded (`make seed`), and a global administrator's email and
// password: by default the e2e suite's owner from e2e/.state.json, or
// SHOT_EMAIL / SHOT_PASSWORD. SHOT_OUT changes the folder (a skin review, say).
//
//   node scripts/screenshots.mjs
import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const UI = process.env.SHOT_UI ?? "http://localhost:3110";
const OUT = process.env.SHOT_OUT ?? join(here, "..", "..", "site", "assets", "screens");
const TENANT = process.env.SHOT_TENANT ?? "acme";
const LOGIN_TENANT = process.env.SHOT_LOGIN_TENANT ?? "master";
const THEME = process.env.SHOT_THEME ?? "light";

function credentials() {
  if (process.env.SHOT_EMAIL && process.env.SHOT_PASSWORD) return { email: process.env.SHOT_EMAIL, password: process.env.SHOT_PASSWORD };
  const state = JSON.parse(readFileSync(join(here, "..", "e2e", ".state.json"), "utf8"));
  return { email: state.email, password: state.password };
}

async function signIn(page, email, password) {
  await page.getByLabel("Email or username").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
}

/** Wait for every loading placeholder to go, then for the fonts and animations. */
async function settled(page) {
  await page.getByRole("status").filter({ hasText: "Loading" }).first().waitFor({ state: "detached", timeout: 20_000 }).catch(() => undefined);
  await page.evaluate(() => document.fonts.ready);
  await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished.catch(() => undefined))));
  await page.waitForTimeout(250);
}

const { email, password } = credentials();
await mkdir(OUT, { recursive: true });
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: THEME });
await context.addInitScript((theme) => localStorage.setItem("ridm.theme", theme), THEME);
const page = await context.newPage();
const shot = async (name) => {
  await settled(page);
  await page.screenshot({ path: join(OUT, `${name}.png`) });
  console.log(`wrote ${name}.png`);
};

// The sign-in page, as the acme tenant brands it (the real page on a stand-in flow).
await page.goto(`${UI}/login/?tenant=${TENANT}&preview=1`);
await page.getByRole("heading", { name: "Sign in" }).waitFor();
await shot("login");

// The admin console, signed in through the login tenant, looking at the acme tenant.
await page.goto(`${UI}/console/?tenant=${LOGIN_TENANT}`);
await page.getByLabel("Tenant").fill(LOGIN_TENANT);
await page.getByRole("button", { name: "Continue", exact: true }).click();
await page.waitForURL(/\/login\//);
await signIn(page, email, password);
await page.getByTestId("me-username").waitFor({ timeout: 30_000 });
await page.goto(`${UI}/console/users/?tenant=${TENANT}`);
await page.getByRole("heading", { name: "Users", level: 1 }).waitFor();
await page.getByRole("row").nth(1).waitFor({ timeout: 20_000 });
await shot("console-users");
await page.goto(`${UI}/console/clients/?tenant=${TENANT}`);
await page.getByRole("heading", { name: "Clients", level: 1 }).waitFor();
await page.getByRole("row").nth(1).waitFor({ timeout: 20_000 });
await shot("console-clients");
await page.goto(`${UI}/console/?tenant=${TENANT}`);
await page.getByRole("heading", { level: 1 }).first().waitFor();
await shot("console-overview");

// The account console's security page, as the signed-in administrator sees their own.
await page.goto(`${UI}/account/security/?tenant=${LOGIN_TENANT}`);
await page.getByLabel("Organisation").fill(LOGIN_TENANT);
await page.getByRole("button", { name: "Continue", exact: true }).click();
await page.waitForURL(/\/(login|account)\//, { timeout: 20_000 });
if (page.url().includes("/login/")) await signIn(page, email, password);
await page.getByRole("heading", { name: "Security", level: 1 }).waitFor({ timeout: 20_000 });
await shot("account-security");

await browser.close();
