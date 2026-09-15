import { expect, test, type Page } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/**
 * Users: the windowed table with search and filters, creating a user with
 * a reveal-once temporary password, the profile driven by the tenant's
 * schema, password and security actions, sessions, roles, groups, audit,
 * invitations, import/export and deletion.
 */
test.describe("users", () => {
  const suffix = loadState().email.replace(/\D/g, "").slice(-9);
  const username = `e2e-user-${suffix}`;
  const email = `${username}@example.com`;

  async function openUsers(page: Page) {
    await page.goto(`/console/users/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Users", level: 1 })).toBeVisible({ timeout: 15_000 });
  }
  async function openUser(page: Page, tab?: string) {
    await openUsers(page);
    await page.getByLabel("Search users").fill(username);
    await page.getByRole("link", { name: username, exact: true }).click();
    await expect(page.getByRole("heading", { name: username, level: 1 })).toBeVisible({ timeout: 15_000 });
    if (tab) await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: tab }).click();
  }

  test("declares a profile attribute in the tenant settings", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/settings/?tenant=${TENANT}#profile`);
    await expect(page.getByRole("heading", { name: "Profile attributes" })).toBeVisible({ timeout: 15_000 });
    // Remove leftovers from an earlier run, then add a required enum.
    for (const btn of await page.getByRole("button", { name: /^Remove attribute/ }).all()) await btn.click();
    await page.getByRole("button", { name: "Add attribute" }).click();
    const row = page.getByTestId("attribute-row").last();
    await row.getByLabel("Name").fill("department");
    await row.getByLabel("Type").selectOption("enum");
    await row.getByLabel("Label").fill("Department");
    await row.getByLabel("Allowed values").fill("eng");
    await page.keyboard.press("Enter");
    await row.getByLabel("Allowed values").fill("sales");
    await page.keyboard.press("Enter");
    await row.getByRole("checkbox", { name: "userinfo" }).check();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ }).first()).toBeVisible({ timeout: 10_000 });
    await expectAccessible(page);
  });

  test("creates a user with a temporary password and edits the profile", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openUsers(page);
    await expectAccessible(page);
    await page.getByRole("button", { name: "New user" }).click();
    const dialog = page.getByRole("dialog", { name: "New user" });
    await dialog.getByLabel("Username").fill(username);
    await dialog.getByLabel("Email").fill(email);
    await dialog.getByRole("button", { name: "Create user" }).click();
    const reveal = page.getByRole("dialog", { name: `${username} created` });
    await expect(reveal.getByTestId("secret-value")).not.toBeEmpty({ timeout: 15_000 });
    await reveal.getByRole("button", { name: "I have stored it" }).click();
    await expect(page.getByRole("heading", { name: username, level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("Must change password", { exact: true })).toBeVisible();

    // Profile per schema: the enum declared in settings shows as a select.
    await page.getByLabel("Department").selectOption("sales");
    await page.getByRole("textbox", { name: "Phone" }).fill("+15550100");
    // Created as verified (the dialog's default); switch it off.
    await expect(page.getByRole("switch", { name: "Email verified" })).toHaveAttribute("aria-checked", "true");
    await page.getByRole("switch", { name: "Email verified" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await page.reload();
    await expect(page.getByLabel("Department")).toHaveValue("sales", { timeout: 15_000 });
    await expect(page.getByRole("textbox", { name: "Phone" })).toHaveValue("+15550100");
    await expect(page.getByRole("switch", { name: "Email verified" })).toHaveAttribute("aria-checked", "false");
    await expectAccessible(page);
  });

  test("table search and status filter find the user", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openUsers(page);
    await page.getByLabel("Search users").fill(username);
    await expect(page.getByRole("row", { name: new RegExp(username) })).toBeVisible({ timeout: 10_000 });
    await page.getByLabel("Status").selectOption("disabled");
    await expect(page.getByText("No user matches.")).toBeVisible({ timeout: 10_000 });
    await page.getByLabel("Status").selectOption("");
    await expect(page.getByRole("row", { name: new RegExp(username) })).toBeVisible({ timeout: 10_000 });
  });

  test("password, roles, groups, sessions and audit tabs", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openUser(page, "Password & credentials");
    await expect(page.getByText("At next sign-in")).toBeVisible();
    await page.getByLabel("Replace the password").selectOption("set");
    await page.getByLabel("New password").fill("correct-horse-battery-staple-2");
    await page.getByRole("switch", { name: "Require a change at next sign-in" }).click();
    await page.getByRole("button", { name: "Set password" }).click();
    await expect(page.locator('dt:has-text("Change required") + dd')).toHaveText("No", { timeout: 10_000 });
    await expectAccessible(page);

    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Roles" }).click();
    await page.getByLabel("Role to assign").selectOption({ label: "ridm:viewer" });
    await page.getByRole("button", { name: "Assign" }).click();
    await expect(page.getByRole("listitem").filter({ hasText: "ridm:viewer" })).toBeVisible({ timeout: 10_000 });
    await page.getByRole("listitem").filter({ hasText: "ridm:viewer" }).getByRole("button", { name: "Remove" }).click();
    await expect(page.getByText("No direct roles.")).toBeVisible({ timeout: 10_000 });

    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Groups" }).click();
    await expect(page.getByText("No groups.")).toBeVisible({ timeout: 10_000 });

    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Sessions & devices" }).click();
    await expect(page.getByText("No live sessions.")).toBeVisible({ timeout: 10_000 });

    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Audit" }).click();
    await expect(page.getByText("user.created")).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: /user.created/ }).click();
    await expect(page.getByLabel("Event payload")).toBeVisible();
    await expectAccessible(page);
  });

  test("invites, imports (dry run) and exports", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openUsers(page);
    await page.getByRole("button", { name: "Invite" }).click();
    const invite = page.getByRole("dialog", { name: "Invite someone" });
    await invite.getByLabel("Email").fill(`invite-${suffix}@example.com`);
    await invite.getByRole("checkbox", { name: "ridm:viewer" }).check();
    await invite.getByRole("button", { name: "Send invitation" }).click();
    await expect(invite.getByRole("status")).toContainText("Invitation sent", { timeout: 10_000 });
    await expectAccessible(page);
    await invite.getByRole("button", { name: "Done" }).click();
    await page.getByRole("link", { name: "Open invitations" }).click();
    await expect(page.getByRole("row", { name: new RegExp(`invite-${suffix}`) })).toBeVisible({ timeout: 10_000 });
    await page.getByRole("row", { name: new RegExp(`invite-${suffix}`) }).getByRole("button", { name: "Revoke" }).click();
    await expect(page.getByRole("row", { name: new RegExp(`invite-${suffix}`) })).toBeHidden({ timeout: 10_000 });

    await page.locator("#main").getByRole("link", { name: "Users", exact: true }).click();
    await page.getByRole("button", { name: "Import" }).click();
    const imp = page.getByRole("dialog", { name: "Import users" });
    await imp.getByLabel("Users to import").fill(JSON.stringify([{ username: `imp-${suffix}`, email: `imp-${suffix}@example.com` }, { username: "" }]));
    await imp.getByRole("button", { name: "Dry run" }).click();
    await expect(imp.getByRole("status")).toContainText("1 would be created", { timeout: 15_000 });
    await expect(imp.getByRole("status")).toContainText("1 failed");
    await expect(imp.getByText(/Row 2/)).toBeVisible();
    await expectAccessible(page);
    await imp.getByRole("button", { name: "Done" }).click();

    await page.getByRole("button", { name: "Export" }).click();
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("dialog", { name: "Export users" }).getByRole("button", { name: "Download" }).click()]);
    expect(download.suggestedFilename()).toBe(`${TENANT}-users.json`);
    const text = await (await download.createReadStream()).toArray().then((chunks) => Buffer.concat(chunks).toString("utf8"));
    expect(text).toContain(username);
  });

  test("disables and deletes the user", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openUser(page);
    await page.getByRole("button", { name: "Disable" }).click();
    await expect(page.getByRole("button", { name: "Enable" })).toBeVisible({ timeout: 10_000 });
    await page.getByRole("button", { name: "Delete user" }).click();
    await page.getByRole("dialog", { name: `Delete ${username}?` }).getByRole("button", { name: "Delete user" }).click();
    await page.waitForURL(/\/console\/users\/\?tenant=master$/, { timeout: 15_000 });
    await page.getByLabel("Search users").fill(username);
    await expect(page.getByText("No user matches.")).toBeVisible({ timeout: 10_000 });
  });
});
