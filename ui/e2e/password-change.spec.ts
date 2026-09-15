import { expect, test } from "@playwright/test";
import {
  alertOf,
  expectAccessible,
  finishAuthorization,
  loadState,
  loginWithPassword,
  mailpit,
  registerVerifiedUser,
  tenantSql,
} from "./helpers";

test("a forced password change is required at login, then only the new password works", async ({ page }) => {
  const s = loadState();
  const u = await registerVerifiedUser(s.client_id, s.ui, "forced");
  tenantSql(`UPDATE users SET must_change_password = true WHERE email = '${u.email}'`);

  await loginWithPassword(page, { ...s, ...u });
  await expect(page.getByRole("heading", { name: "Choose a new password" })).toBeVisible();
  await expectAccessible(page);

  const fresh = "another-strong-passphrase-42";
  await page.getByLabel("New password", { exact: true }).fill(fresh);
  await page.getByLabel("Confirm new password").fill("something-else-entirely");
  await expect(page.getByText("The passwords do not match.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Continue" })).toBeDisabled();
  await expectAccessible(page);

  await page.getByLabel("Confirm new password").fill(fresh);
  await page.getByRole("button", { name: "Continue" }).click();
  await finishAuthorization(page);

  // The user is notified about the change.
  const notice = await mailpit.waitFor(u.email);
  expect(notice.subject).toContain("password was changed");

  // The old password no longer works; the new one does.
  await loginWithPassword(page, { ...s, ...u });
  await expect(alertOf(page)).toContainText("Incorrect");
  await page.getByLabel("Password", { exact: true }).fill(fresh);
  await page.getByRole("button", { name: "Continue" }).click();
  await finishAuthorization(page);
});
