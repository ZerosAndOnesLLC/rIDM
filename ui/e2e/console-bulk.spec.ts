import { expect, test, type Page } from "@playwright/test";
import { confirmDialog, consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/**
 * Bulk actions (Phase 15.11): checkbox selection on the users, invitations
 * and IP-rules lists, the floating bar, one confirmation and one summary
 * toast for the whole run, and the list filters living in the URL.
 */
test.describe("bulk actions", () => {
  const suffix = loadState().email.replace(/\D/g, "").slice(-9);
  const names = [`e2e-bulk-a-${suffix}`, `e2e-bulk-b-${suffix}`];

  async function createUser(page: Page, username: string) {
    await page.goto(`/console/users/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Users", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New user" }).click();
    const dialog = page.getByRole("dialog", { name: "New user" });
    await dialog.getByLabel("Username").fill(username);
    await dialog.getByLabel("Email").fill(`${username}@example.com`);
    await dialog.getByRole("button", { name: "Create user" }).click();
    const reveal = page.getByRole("dialog", { name: `${username} created` });
    await expect(reveal.getByTestId("secret-value")).not.toBeEmpty({ timeout: 15_000 });
    await reveal.getByRole("button", { name: "I have stored it" }).click();
    await expect(page.getByRole("heading", { name: username, level: 1 })).toBeVisible({ timeout: 15_000 });
  }

  test("users: filters in the URL, select two, disable, then delete", async ({ page }) => {
    await consoleLogin(page, loadState());
    for (const n of names) await createUser(page, n);

    // The search filter is part of the address: a reload keeps it.
    await page.goto(`/console/users/?tenant=${TENANT}&q=e2e-bulk-`);
    for (const n of names) await expect(page.getByRole("row", { name: new RegExp(n) })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByLabel("Search users")).toHaveValue("e2e-bulk-");
    await page.getByRole("columnheader", { name: "Email" }).getByRole("button").click();
    await page.waitForURL(/sort=email/);

    for (const n of names) await page.getByRole("checkbox", { name: `Select ${n}` }).check();
    const bar = page.getByRole("region", { name: "Selected users" });
    await expect(bar).toContainText("2");
    await expectAccessible(page);
    await bar.getByRole("button", { name: "Disable" }).click();
    await expect(page.getByRole("status").filter({ hasText: "2 users disabled" })).toBeVisible({ timeout: 15_000 });
    for (const n of names) await expect(page.getByRole("row", { name: new RegExp(n) })).toContainText("Disabled", { timeout: 15_000 });
    await expect(bar).toBeHidden();

    for (const n of names) await page.getByRole("checkbox", { name: `Select ${n}` }).check();
    await bar.getByRole("button", { name: "Delete" }).click();
    await confirmDialog(page);
    await expect(page.getByRole("status").filter({ hasText: "2 users deleted" })).toBeVisible({ timeout: 15_000 });
    for (const n of names) await expect(page.getByRole("row", { name: new RegExp(n) })).toBeHidden({ timeout: 15_000 });
  });

  test("ip rules: select two, delete both at once", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/ip-rules/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "IP rules", level: 1 })).toBeVisible({ timeout: 15_000 });
    const cidrs = ["198.51.100.0/25", "198.51.100.128/25"];
    for (const cidr of cidrs) {
      await page.getByLabel("Network (CIDR)").fill(cidr);
      await page.getByRole("button", { name: "Add rule" }).click();
      await expect(page.getByRole("row").filter({ hasText: cidr })).toBeVisible({ timeout: 10_000 });
    }
    for (const cidr of cidrs) await page.getByRole("checkbox", { name: `Select ${cidr}` }).check();
    const bar = page.getByRole("region", { name: "Selected rules" });
    await bar.getByRole("button", { name: "Delete" }).click();
    await confirmDialog(page);
    await expect(page.getByRole("status").filter({ hasText: "2 rules deleted" })).toBeVisible({ timeout: 15_000 });
    for (const cidr of cidrs) await expect(page.getByRole("row").filter({ hasText: cidr })).toBeHidden({ timeout: 10_000 });
  });

  test("invitations: select and revoke", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/users/?tenant=${TENANT}`);
    await page.getByRole("button", { name: "Invite" }).click();
    const invite = page.getByRole("dialog", { name: "Invite someone" });
    const email = `bulk-invite-${suffix}@example.com`;
    await invite.getByLabel("Email").fill(email);
    await invite.getByRole("button", { name: "Send invitation" }).click();
    await expect(invite.getByRole("status")).toContainText("Invitation sent", { timeout: 10_000 });
    await invite.getByRole("button", { name: "Done" }).click();
    await page.goto(`/console/users/?tenant=${TENANT}&view=invitations`);
    await expect(page.getByRole("row", { name: new RegExp(email) })).toBeVisible({ timeout: 10_000 });
    await page.getByRole("checkbox", { name: `Select ${email}` }).check();
    await page.getByRole("region", { name: "Selected invitations" }).getByRole("button", { name: "Revoke" }).click();
    await confirmDialog(page);
    await expect(page.getByRole("status").filter({ hasText: "1 invitation revoked" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("row", { name: new RegExp(email) })).toBeHidden({ timeout: 10_000 });
  });
});
