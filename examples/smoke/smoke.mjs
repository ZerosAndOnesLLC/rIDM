// The example applications, signed into for real: headless Chromium against
// the three examples and rIDM's own sign-in pages, all started by run.sh.
//
//   1. the orders API refuses an anonymous call with an RFC 6750 challenge;
//   2. dana signs in to the server-side web app with a password and places an
//      order through it (orders:write);
//   3. the SPA, in the same browser, picks the SSO session up with
//      `prompt=none` — no login form — sees that order and places another;
//   4. signing out of the SPA ends the rIDM session, and back-channel logout
//      ends the web app's session with it;
//   5. sam (orders-reader) sees the orders in both apps, and the orders API
//      refuses his order with 403.
//
// Playwright comes from ui/ (its pinned @playwright/test and the Chromium
// `npx playwright install` put there), so the examples carry no npm project
// of their own for this.

import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const { chromium } = createRequire(join(ROOT, "ui", "package.json"))("@playwright/test");

const need = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required (run.sh sets it)`);
  return v.replace(/\/+$/, "");
};
const UI = need("UI_URL");
const WEB = need("WEB_URL");
const SPA = need("SPA_URL");
const ORDERS = need("ORDERS_URL");
const PASSWORD = need("DEMO_PASSWORD");
const SHOTS = process.env.SMOKE_SHOTS || join(ROOT, "target", "smoke");
const STEP = 30_000;

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const check = (ok, what) => {
  if (!ok) throw new Error(what);
};

/** The login form on rIDM's pages, then back to wherever the flow returns. */
async function passwordSignIn(page, username, back) {
  await page.waitForURL((u) => u.href.startsWith(`${UI}/login`), { timeout: STEP });
  await page.fill("input[name=identifier]", username);
  await page.fill("input[name=password]", PASSWORD);
  await page.click("#login-submit");
  await page.waitForURL((u) => u.href.startsWith(back), { timeout: STEP });
}

async function webSignIn(page, username) {
  await page.goto(`${WEB}/`);
  await page.click("text=Sign in");
  await passwordSignIn(page, username, WEB);
  await page.getByText("Signed in as").waitFor({ timeout: STEP });
}

/** Reload `page` until `done()` holds; back-channel delivery is not instant. */
async function eventually(page, done, what, ms = 30_000) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await done()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await page.waitForTimeout(1000);
    await page.reload();
  }
}

const browser = await chromium.launch();
const pages = [];
try {
  log("anonymous call to the orders API");
  const anonymous = await fetch(`${ORDERS}/orders`);
  check(anonymous.status === 401, `GET /orders without a token: ${anonymous.status}`);
  check(
    (anonymous.headers.get("www-authenticate") ?? "").startsWith("Bearer"),
    "no Bearer challenge on the 401",
  );

  const dana = await browser.newContext();
  const web = await dana.newPage();
  pages.push(web);
  log("dana signs in to the web app");
  await webSignIn(web, "dana");
  check((await web.content()).includes("orders:write"), "dana's session lacks orders:write");
  await web.fill("input[name=item]", "Anvil");
  await web.fill("input[name=quantity]", "2");
  await web.click("text=Place order");
  await web.getByText("Order placed.").waitFor({ timeout: STEP });
  await web.locator("td", { hasText: "Anvil" }).waitFor({ timeout: STEP });

  log("the SPA picks the session up without a login form");
  const spa = await dana.newPage();
  pages.push(spa);
  const loginShown = [];
  spa.on("framenavigated", (frame) => {
    if (frame === spa.mainFrame() && frame.url().startsWith(`${UI}/login`)) loginShown.push(frame.url());
  });
  await spa.goto(`${SPA}/`);
  await spa.getByText("Signed in as").waitFor({ timeout: STEP });
  check(loginShown.length === 0, `the SPA's silent sign-in showed a login form: ${loginShown[0]}`);
  // The orders API is one service behind both apps.
  await spa.locator("td", { hasText: "Anvil" }).waitFor({ timeout: STEP });
  await spa.fill("input[name=item]", "Rope");
  await spa.click("text=Place order");
  await spa.getByText("Order placed.").waitFor({ timeout: STEP });
  await spa.locator("td", { hasText: "Rope" }).waitFor({ timeout: STEP });

  log("signing out of the SPA ends the web app's session (back-channel)");
  await spa.click("text=Sign out");
  // A confirmation page, when rIDM asks for one, is one click.
  const confirm = spa.locator("#logout-confirm");
  await Promise.race([
    confirm.waitFor({ timeout: STEP }).then(() => confirm.click()),
    spa.waitForURL((u) => u.href.startsWith(SPA), { timeout: STEP }),
  ]);
  await spa.waitForURL((u) => u.href.startsWith(SPA), { timeout: STEP });
  await spa.getByRole("button", { name: "Sign in" }).waitFor({ timeout: STEP });
  await eventually(
    web,
    async () => (await web.getByText("Signed in as").count()) === 0,
    "the web app to drop dana's session",
  );
  check((await web.locator("a", { hasText: "Sign in" }).count()) === 1, "web app shows no Sign in link");
  await dana.close();

  const sam = await browser.newContext();
  const samWeb = await sam.newPage();
  pages.push(samWeb);
  log("sam (orders-reader) reads orders and may not place one");
  await webSignIn(samWeb, "sam");
  const html = await samWeb.content();
  check(!html.includes("orders:write"), "sam holds orders:write");
  check(html.includes("may read orders but not place them"), "no read-only notice for sam");
  await samWeb.locator("td", { hasText: "Rope" }).waitFor({ timeout: STEP });
  // The form is hidden from him; the API is what actually refuses.
  const refused = await samWeb.request.post(`${WEB}/orders`, { form: { item: "Nope", quantity: "1" } });
  const body = await refused.text();
  check(body.includes("The orders API refused: 403"), `sam's order was not refused by the API: ${body.slice(0, 300)}`);
  const samSpa = await sam.newPage();
  pages.push(samSpa);
  await samSpa.goto(`${SPA}/`);
  await samSpa.getByText("may read orders but not place them").waitFor({ timeout: STEP });
  await sam.close();

  log("examples smoke passed");
} catch (err) {
  mkdirSync(SHOTS, { recursive: true });
  for (const [i, page] of pages.entries()) {
    if (page.isClosed()) continue;
    await page.screenshot({ path: join(SHOTS, `failure-${i}.png`), fullPage: true }).catch(() => {});
    log(`page ${i} at ${page.url()}`);
  }
  throw err;
} finally {
  await browser.close();
}
