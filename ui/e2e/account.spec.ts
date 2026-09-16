import { createHmac } from "node:crypto";
import { expect, test } from "@playwright/test";
import { authorizeUrl, expectAccessible, finishAuthorization, loadState, loginWithPassword, tenantId, tenantSql, TENANT } from "./helpers";

/**
 * The account console (`/account/`): sign in through the tenant, add an
 * authenticator app as the second step (recovery codes shown once), see it
 * listed, renew the recovery codes, trust a browser during a step-up and
 * forget it again, and remove the factor. Changing anything needs a
 * recent sign-in; the second sign-in below is old enough for nothing, so
 * the page never has to re-authenticate within the test.
 */

function base32Decode(s: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of s.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function totpAt(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const o = (h[h.length - 1] ?? 0) & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

const usedSteps = new Set<number>();
function freshCode(secret: string): string {
  const current = Math.floor(Date.now() / 1000 / 30);
  const step = [current + 1, current, current - 1].find((c) => !usedSteps.has(c));
  if (step === undefined) throw new Error("every step in the window was used");
  usedSteps.add(step);
  return totpAt(secret, step);
}

test.describe("account console", () => {
  test.describe.configure({ mode: "serial" });
  let secret = "";

  test.afterAll(() => {
    const tid = tenantId();
    const user = `(SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${loadState().email}')`;
    tenantSql(`DELETE FROM credentials WHERE tenant_id = '${tid}' AND user_id = ${user} AND type IN ('totp','recovery_code')`);
    tenantSql(`DELETE FROM trusted_devices WHERE tenant_id = '${tid}' AND user_id = ${user}`);
  });

  test("signs in and adds an authenticator app", async ({ page }) => {
    const s = loadState();
    await page.goto(`/account/security/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Manage your account" })).toBeVisible();
    await expect(page.getByLabel("Organisation")).toHaveValue(TENANT);
    await expectAccessible(page);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.waitForURL(/\/login\//);
    await page.getByLabel("Email or username").fill(s.email);
    await page.getByLabel("Password", { exact: true }).fill(s.password);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.waitForURL(/\/account\/security\/(\?.*)?$/, { timeout: 20_000 });
    await expect(page.getByRole("heading", { name: "Security", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("No second step is set up yet.")).toBeVisible();
    await expectAccessible(page);

    await page.getByRole("button", { name: "Add an authenticator app" }).click();
    const dialog = page.getByRole("dialog", { name: "Add an authenticator app" });
    await expect(dialog.getByRole("img", { name: /QR code to add/ })).toBeVisible({ timeout: 15_000 });
    secret = (await dialog.getByTestId("totp-secret").textContent())?.trim() ?? "";
    expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
    await dialog.getByLabel("Code").fill(freshCode(secret));
    await dialog.getByLabel("Name this device (optional)").fill("Laptop");
    await dialog.getByRole("button", { name: "Verify and finish" }).click();
    const codes = page.getByRole("dialog");
    await expect(codes.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible({ timeout: 15_000 });
    expect(await codes.getByRole("list", { name: "Save your recovery codes" }).getByRole("listitem").count()).toBe(10);
    await codes.getByRole("button", { name: "I have saved my codes" }).click();

    const list = page.getByRole("list", { name: "Two-step verification" });
    await expect(list.getByRole("listitem")).toHaveCount(1);
    await expect(list).toContainText("Authenticator app");
    await expect(list).toContainText("Laptop");
    await expect(page.getByText("10 codes left")).toBeVisible();
    await expectAccessible(page);
  });

  test("a step-up trusts this browser; the console lists and forgets it, renews codes and removes the app", async ({ page }) => {
    const s = loadState();
    // Sign in with the app and tick "don't ask again": the browser becomes trusted.
    await loginWithPassword(page, s, { acr_values: "urn:ridm:acr:mfa" });
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await page.getByLabel("Code").fill(freshCode(secret));
    await page.getByLabel("Don't ask again on this device").check();
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await finishAuthorization(page);

    // The account console reuses that session: the sign-in is recent and passed the second step.
    await page.goto(authorizeUrl(s));
    await finishAuthorization(page);
    await page.goto(`/account/security/?tenant=${TENANT}`);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.waitForURL(/\/account\/security\/(\?.*)?$/, { timeout: 20_000 });
    await expect(page.getByRole("heading", { name: "Security", level: 1 })).toBeVisible({ timeout: 15_000 });

    const devices = page.getByRole("heading", { name: "Trusted devices" }).locator("..").locator("..");
    await expect(devices.getByRole("button", { name: "Forget", exact: true })).toHaveCount(1, { timeout: 15_000 });
    await devices.getByRole("button", { name: "Forget", exact: true }).click();
    await expect(page.getByText("No trusted devices.")).toBeVisible({ timeout: 15_000 });

    await page.getByRole("button", { name: "Get new codes" }).click();
    const confirm = page.getByRole("dialog", { name: "Get new codes" });
    await confirm.getByRole("button", { name: "Get new codes" }).click();
    const codes = page.getByRole("dialog");
    await expect(codes.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible({ timeout: 15_000 });
    await codes.getByRole("button", { name: "I have saved my codes" }).click();

    await page.getByRole("button", { name: "Remove" }).click();
    const remove = page.getByRole("dialog", { name: /Remove Authenticator app/ });
    await expect(remove.getByText(/only second step/)).toBeVisible();
    await remove.getByRole("button", { name: "Remove" }).click();
    await expect(page.getByText("No second step is set up yet.")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: "Add an authenticator app" })).toBeVisible();
  });
});
