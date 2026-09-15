import { expect, test } from "@playwright/test";
import { alertOf, authorizeUrl, expectAccessible, loadState, registerVerifiedUser } from "./helpers";

// The tenant default: ten consecutive failures lock the account for a while.
const MAX_FAILURES = 10;

test("repeated wrong passwords lock the account, and the right password is then refused too", async ({ page }) => {
  const s = loadState();
  const u = await registerVerifiedUser(s.client_id, s.ui, "lock");
  await page.goto(authorizeUrl(s, { prompt: "login" }));
  await page.waitForURL(/\/login\//);
  await page.getByLabel("Email or username").fill(u.email);

  for (let i = 0; i <= MAX_FAILURES; i++) {
    await page.getByLabel("Password", { exact: true }).fill(`wrong-${i}`);
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(alertOf(page)).toBeVisible();
  }
  await expect(alertOf(page)).toContainText("Too many failed attempts");
  await expectAccessible(page);

  await page.getByLabel("Password", { exact: true }).fill(u.password);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(alertOf(page)).toContainText("Too many failed attempts");
  await expect(page).toHaveURL(/\/login\//);
});
