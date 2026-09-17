// The browser the conformance suite cannot bring itself: the suite's built-in
// HtmlUnit cannot run rIDM's React pages, so tests are configured without
// browser tasks and every URL they leave pending is visited here in headless
// Chromium (Playwright). One browser context per test module keeps the
// session across a module's authorizations (prompt=none, id_token_hint,
// max_age); modules start signed out. Runs inside the suite's network:
//   CONFORMANCE_SERVER=https://nginx:8443/ OP_USER=... OP_PASSWORD=... node driver.mjs

import { chromium } from "playwright";
import { mkdirSync, writeFileSync } from "node:fs";

const SERVER = (process.env.CONFORMANCE_SERVER || "https://nginx:8443/").replace(/\/?$/, "/");
const USER = process.env.OP_USER;
const PASSWORD = process.env.OP_PASSWORD;
const POLL_MS = 1000;
const STEP_TIMEOUT_MS = 20_000;
const SHOTS = process.env.DRIVER_SHOTS || "";
if (!USER || !PASSWORD) throw new Error("OP_USER and OP_PASSWORD are required");
if (SHOTS) mkdirSync(SHOTS, { recursive: true });

const log = (...a) => console.log(new Date().toISOString(), ...a);
// The suite's certificate is self-signed.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const api = async (path, init) => {
  const res = await fetch(SERVER + path, { headers: { accept: "application/json" }, ...init });
  if (!res.ok) throw new Error(`${path}: ${res.status} ${(await res.text()).slice(0, 120)}`);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
};

const browser = await chromium.launch({ args: ["--ignore-certificate-errors"] });
const contexts = new Map(); // module id → { context, visited: Set<string> }
const finished = new Set();

async function contextFor(id) {
  let entry = contexts.get(id);
  if (!entry) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    entry = { context, visited: new Set(), uploaded: new Set() };
    contexts.set(id, entry);
  }
  return entry;
}

/** A small JPEG of the page as a data URL, the form the suite's image API takes. */
async function shot(page) {
  const buf = await page.screenshot({ type: "jpeg", quality: 45 }).catch(() => null);
  return buf ? `data:image/jpeg;base64,${buf.toString("base64")}` : null;
}

/**
 * Drive one page until the suite's callback page shows up or nothing more
 * happens. Returns the outcome and the screenshot of the last login page shown
 * (what the tests that ask for evidence of a login prompt want to see).
 */
async function drive(page, id, url) {
  await page.goto(url, { waitUntil: "load", timeout: STEP_TIMEOUT_MS }).catch((e) => log(id, "goto", e.message));
  const deadline = Date.now() + 60_000;
  let last = "";
  let submitted = false;
  const clicked = new Set();
  let evidence = null;
  const done = (outcome) => ({ outcome, evidence });
  while (Date.now() < deadline) {
    const here = page.url();
    const path = URL.canParse(here) ? new URL(here).pathname : here;
    if (/\/test\/[^/]+\/(callback|post_logout_redirect)/.test(path) || (await page.locator("#submission_complete").count()) > 0) {
      log(id, "reached", here.slice(0, 80));
      return done("callback");
    }
    // The login form: the identifier may arrive prefilled (login_hint), so
    // the password field decides; one submission per page.
    if (!submitted && (await page.locator("input[name=password]").count()) > 0) {
      log(id, "login form");
      evidence = await shot(page);
      if ((await page.locator("input[name=identifier]").inputValue()) === "") await page.fill("input[name=identifier]", USER);
      await page.fill("input[name=password]", PASSWORD);
      await page.click("#login-submit", { timeout: STEP_TIMEOUT_MS });
      submitted = true;
      await page.waitForTimeout(500);
      continue;
    }
    // Consent and logout are one click each: while the request is in flight
    // the button is disabled, and clicking it again would wait out
    // Playwright's actionability timeout for nothing.
    for (const [what, sel] of [["consent", "#consent-approve"], ["logout confirm", "#logout-confirm"]]) {
      if (clicked.has(sel) || (await page.locator(sel).count()) === 0) continue;
      log(id, what);
      clicked.add(sel);
      await page.click(sel, { timeout: STEP_TIMEOUT_MS }).catch((e) => log(id, what, e.message.split("\n")[0]));
      await page.waitForTimeout(500);
    }
    if (clicked.size > 0 && page.url() !== here) continue;
    // Settled somewhere else (an error page from the OP, or a page that
    // finished on its own): give it a moment, then report where it ended. A
    // page still loading its flow, or one still framing the relying parties
    // it is signing out of, keeps its turn until the deadline.
    const loading = (await page.locator("[role=status], iframe").count()) > 0;
    if (here === last && !loading) {
      await page.waitForTimeout(1500);
      if (page.url() === here) {
        const text = (await page.locator("body").innerText().catch(() => "")).slice(0, 120).replace(/\s+/g, " ");
        log(id, "settled at", here.slice(0, 100), "|", text);
        return done("settled");
      }
    }
    last = here;
    await page.waitForTimeout(300);
  }
  log(id, "gave up at", page.url().slice(0, 100));
  return done("timeout");
}

/**
 * Tests that must see a login prompt leave an image placeholder in their log
 * and wait for the upload: fill every unfilled one with the latest login page.
 */
async function fillPlaceholders(id, entry, image) {
  const entries = await api(`api/log/${id}`).catch(() => []);
  for (const e of entries) {
    const placeholder = e.upload;
    if (!placeholder || entry.uploaded.has(placeholder)) continue;
    entry.uploaded.add(placeholder);
    await api(`api/log/${id}/images/${encodeURIComponent(placeholder)}`, { method: "POST", body: image })
      .then(() => log(id, "uploaded evidence for", e.src))
      .catch((err) => log(id, "upload failed", err.message));
  }
}

async function tick() {
  const running = await api("api/runner/running").catch((e) => {
    log("running list failed:", e.message);
    return [];
  });
  for (const id of running) {
    if (finished.has(id)) continue;
    let info;
    try {
      info = await api(`api/runner/${id}`);
    } catch {
      continue;
    }
    const urls = info?.browser?.urls || [];
    const entry = await contextFor(id);
    for (const url of urls) {
      if (entry.visited.has(url)) continue;
      entry.visited.add(url);
      log(id, "visit", url.slice(0, 100));
      const page = await entry.context.newPage();
      try {
        const { outcome, evidence } = await drive(page, id, url);
        if (SHOTS) await page.screenshot({ path: `${SHOTS}/${id}-${entry.visited.size}.png`, fullPage: true }).catch(() => {});
        log(id, outcome);
        entry.evidence = evidence || entry.evidence || (await shot(page));
      } finally {
        await page.close().catch(() => {});
      }
    }
  }
  // A placeholder may appear after the visit that showed the page it wants.
  for (const [id, entry] of contexts) {
    if (running.includes(id) && entry.evidence) await fillPlaceholders(id, entry, entry.evidence);
  }
  // Drop contexts of modules that are no longer running.
  for (const id of [...contexts.keys()]) {
    if (!running.includes(id)) {
      const entry = contexts.get(id);
      contexts.delete(id);
      finished.add(id);
      await entry.context.close().catch(() => {});
    }
  }
}

log("driver up against", SERVER);
for (;;) {
  try {
    await tick();
  } catch (e) {
    log("tick failed", e.message);
  }
  await new Promise((r) => setTimeout(r, POLL_MS));
}
