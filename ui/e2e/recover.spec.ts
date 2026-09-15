import { expect, test } from "@playwright/test";
import { expectAccessible, finishAuthorization, loadState, loginWithPassword, mailpit, saveState, t } from "./helpers";

test("password recovery by emailed link, then login with the new password", async ({ page }) => {
  const s = loadState();
  await page.goto(`/recover/?tenant=${encodeURIComponent(t("").slice(3))}`);
  await expect(page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel("Email or username").fill(s.email);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(page.getByRole("status")).toContainText("reset link");

  const mail = await mailpit.waitFor(s.email);
  const link = mail.links.find((l) => l.includes("/recover/") && l.includes("token="));
  expect(link, mail.text).toBeTruthy();
  await page.goto(link!);
  const newPassword = `recovered-passphrase-${Date.now()}`;
  await page.getByLabel("New password", { exact: true }).fill(newPassword);
  await page.getByLabel("Confirm new password").fill(newPassword);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("status")).toContainText("has been reset");
  await expectAccessible(page);

  const updated = { ...s, password: newPassword };
  saveState(updated);
  await loginWithPassword(page, updated);
  await finishAuthorization(page);
});
