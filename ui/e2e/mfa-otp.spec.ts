import { expect, test } from "@playwright/test";
import { alertOf, expectAccessible, finishAuthorization, loadState, loginWithPassword, mailpit, tenantId, tenantSql } from "./helpers";

/**
 * Email code as the second factor: the master tenant offers it next to the
 * authenticator app and passkeys, so a client step-up shows the chooser;
 * enrolling sends a code to the account's address, the next step-up sends
 * one again and verifies it, and "Send again" works.
 */

const STEP_UP = { acr_values: "urn:ridm:acr:mfa" };

/** The code in an OTP email (its subject carries `code:` too). */
async function emailedCode(to: string): Promise<string> {
  const mail = await mailpit.waitFor(to, 15_000, "code:");
  const m = /code is (\d{6})/.exec(mail.text);
  if (!m) throw new Error(`no code in ${mail.text}`);
  return m[1] ?? "";
}

test.describe("email code second step", () => {
  test.describe.configure({ mode: "serial" });

  test.afterAll(() => {
    // Leave the shared e2e user as the other specs expect it.
    const tid = tenantId();
    tenantSql(`DELETE FROM credentials WHERE tenant_id = '${tid}' AND user_id = (SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${loadState().email}') AND type IN ('email_otp','recovery_code')`);
  });

  test("the chooser enrols codes by email", async ({ page }) => {
    const s = loadState();
    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: "Set up two-step verification" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: /^Authenticator app/ })).toBeVisible();
    await page.getByRole("button", { name: /^Email code/ }).click();
    await expect(page.getByRole("heading", { name: "Verify your email address" })).toBeVisible();
    const masked = `${s.email[0]}•••@${s.email.split("@")[1]}`;
    await expect(page.getByText(`We sent a code to ${masked}`)).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);
    const code = await emailedCode(s.email);

    // A wrong code is refused and counted; the enrolment stays open.
    const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");
    await page.getByLabel("Code").fill(wrong);
    await page.getByRole("button", { name: "Verify and finish" }).click();
    await expect(alertOf(page)).toContainText(/invalid/i);

    await page.getByLabel("Code").fill(code);
    await page.getByRole("button", { name: "Verify and finish" }).click();
    await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible({ timeout: 15_000 });
    const recovery = await page.getByRole("list", { name: "Save your recovery codes" }).getByRole("listitem").allTextContents();
    expect(recovery).toHaveLength(10);
    await page.getByRole("button", { name: "I have saved my codes" }).click();
    await finishAuthorization(page);
  });

  test("the next step-up emails a code and verifies it", async ({ page }) => {
    const s = loadState();
    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: "Two-step verification" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(/We sent a code to/)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: "Use a recovery code" })).toBeVisible();
    await expectAccessible(page);
    const code = await emailedCode(s.email);
    await page.getByLabel("Code").fill(code);
    await page.getByRole("button", { name: "Continue" }).click();
    await finishAuthorization(page);
  });
});
