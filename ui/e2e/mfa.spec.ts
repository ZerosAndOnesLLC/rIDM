import { createHmac } from "node:crypto";
import { expect, test } from "@playwright/test";
import { alertOf, expectAccessible, finishAuthorization, loadState, loginWithPassword, tenantId, tenantSql } from "./helpers";

/**
 * TOTP second factor: a client step-up (`acr_values` ending in `:mfa`) makes
 * the flow ask for one even though the master tenant's policy is off, so
 * the other specs' sign-ins stay untouched. Enrolment (QR + manual key),
 * verification with the app, a recovery code, and the replay guard.
 */

const STEP_UP = { acr_values: "urn:ridm:acr:mfa" };

function base32Decode(s: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const v = alphabet.indexOf(c);
    if (v < 0) throw new Error(`bad base32 char ${c}`);
    bits += v.toString(2).padStart(5, "0");
  }
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

/** RFC 6238 code (SHA-1, 6 digits, 30 s) for the given time step. */
function totpAt(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const o = (h[h.length - 1] ?? 0) & 0xf;
  const v = h.readUInt32BE(o) & 0x7fffffff;
  return String(v % 1_000_000).padStart(6, "0");
}

const usedSteps = new Set<number>();

/**
 * A code the server will accept now: from the latest step inside the drift
 * window (one step either side of the current one) that no earlier test
 * spent, since every step is accepted once.
 */
function freshCode(secret: string): string {
  const current = Math.floor(Date.now() / 1000 / 30);
  const step = [current + 1, current, current - 1].find((c) => !usedSteps.has(c));
  if (step === undefined) throw new Error("every step in the window was used");
  usedSteps.add(step);
  return totpAt(secret, step);
}

test.describe("two-step verification", () => {
  test.describe.configure({ mode: "serial" });
  let secret = "";
  let used = "";
  let recovery: string[] = [];

  test.afterAll(() => {
    // Leave the shared e2e user as the other specs expect it.
    const tid = tenantId();
    tenantSql(`DELETE FROM credentials WHERE tenant_id = '${tid}' AND user_id = (SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${loadState().email}') AND type IN ('totp','recovery_code')`);
  });

  test("first step-up enrols an authenticator and shows recovery codes once", async ({ page }) => {
    const s = loadState();
    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: "Set up two-step verification" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("img", { name: /QR code to add/ })).toBeVisible({ timeout: 15_000 });
    secret = (await page.getByTestId("totp-secret").textContent())?.trim() ?? "";
    expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
    await expectAccessible(page);

    // A wrong proof is refused and counted; the enrolment stays open.
    const proof = freshCode(secret);
    const wrong = String((Number(proof) + 1) % 1_000_000).padStart(6, "0");
    await page.getByLabel("Code").fill(wrong);
    await page.getByRole("button", { name: "Verify and finish" }).click();
    await expect(alertOf(page)).toContainText(/invalid/i);

    await page.getByLabel("Code").fill(proof);
    await page.getByLabel("Name this device (optional)").fill("Laptop");
    await page.getByRole("button", { name: "Verify and finish" }).click();
    await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible({ timeout: 15_000 });
    recovery = (await page.getByRole("list", { name: "Save your recovery codes" }).getByRole("listitem").allTextContents()).map((c) => c.trim());
    expect(recovery).toHaveLength(10);
    for (const c of recovery) expect(c).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
    await expect(page.getByRole("link", { name: "Download as text" })).toHaveAttribute("download", "recovery-codes.txt");
    await expectAccessible(page);
    await page.getByRole("button", { name: "I have saved my codes" }).click();
    await finishAuthorization(page);
  });

  test("the next step-up verifies with the app", async ({ page }) => {
    const s = loadState();
    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: "Two-step verification" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("Enter the code from your authenticator app.")).toBeVisible();
    await expectAccessible(page);
    used = freshCode(secret);
    await page.getByLabel("Code").fill(used);
    await page.getByRole("button", { name: "Continue" }).click();
    await finishAuthorization(page);
  });

  test("a spent code is refused; a recovery code signs in once", async ({ page }) => {
    const s = loadState();
    const first = recovery[0] ?? "";
    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await page.getByLabel("Code").fill(used);
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(alertOf(page)).toContainText(/invalid/i);
    await page.getByRole("button", { name: "Use a recovery code" }).click();
    await expect(page.getByText(/Each works once/)).toBeVisible();
    await expectAccessible(page);
    await page.getByLabel("Recovery code").fill(first.toUpperCase());
    await page.getByRole("button", { name: "Continue" }).click();
    await finishAuthorization(page);

    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await page.getByRole("button", { name: "Use a recovery code" }).click();
    await page.getByLabel("Recovery code").fill(first);
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(alertOf(page)).toContainText(/invalid/i);
    await page.getByRole("button", { name: "Use your authenticator app instead" }).click();
    await page.getByLabel("Code").fill(freshCode(secret));
    await page.getByRole("button", { name: "Continue" }).click();
    await finishAuthorization(page);
  });
});
