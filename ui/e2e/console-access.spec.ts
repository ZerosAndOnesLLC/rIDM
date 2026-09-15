import { expect, test } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/** Groups (tree, roles, members), roles (composites, permissions, holders), resource servers, scopes and claim mappers. */
test.describe("access model", () => {
  const suffix = loadState().email.replace(/\D/g, "").slice(-9);
  const g = `e2e-group-${suffix}`;
  const role = `e2e-role-${suffix}`;
  const rs = `e2e-api-${suffix}`;
  const scope = `e2e-scope-${suffix}`;
  const mapper = `e2e-mapper-${suffix}`;

  test("resource server with a permission, then a role that carries it", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/resource-servers/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Resource servers", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("link", { name: /rIDM admin API/ })).toBeVisible();
    await page.getByRole("button", { name: "New resource server" }).click();
    const dialog = page.getByRole("dialog", { name: "New resource server" });
    await dialog.getByLabel("Name").fill(`E2E API ${suffix}`);
    await dialog.getByLabel("Identifier").fill(`https://${rs}.example.com`);
    await dialog.getByRole("button", { name: "Create" }).click();
    await page.waitForURL(/resource-servers\/\?tenant=master&rs=/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: `E2E API ${suffix}`, level: 2 })).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Token lifetime").fill("600");
    await page.getByRole("switch", { name: "Allow offline access" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await page.getByLabel("Permission name").fill("orders:read");
    await page.getByLabel("Permission description").fill("Read orders");
    await page.getByRole("button", { name: "Add", exact: true }).click();
    await expect(page.getByText("orders:read")).toBeVisible({ timeout: 10_000 });
    await expectAccessible(page);
    await page.reload();
    await expect(page.getByLabel("Token lifetime")).toHaveValue("600", { timeout: 15_000 });

    await page.goto(`/console/roles/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Roles", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("link", { name: /ridm:owner/ })).toBeVisible();
    await page.getByRole("button", { name: "New role" }).click();
    const rd = page.getByRole("dialog", { name: "New role" });
    await rd.getByLabel("Name").fill(role);
    await rd.getByLabel("Description").fill("Reads orders");
    await rd.getByRole("button", { name: "Create role" }).click();
    await page.waitForURL(/roles\/\?tenant=master&role=/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: role, level: 2 })).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Permission to grant").selectOption({ label: `E2E API ${suffix}: orders:read` });
    await page.getByRole("button", { name: "Grant" }).click();
    await expect(page.getByRole("listitem").filter({ hasText: "orders:read" })).toBeVisible({ timeout: 10_000 });
    await page.getByLabel("Role to include").selectOption({ label: "ridm:viewer" });
    await page.getByRole("button", { name: "Include" }).click();
    await expect(page.getByRole("listitem").filter({ hasText: "ridm:viewer" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Nobody holds this role directly.")).toBeVisible();
    await expectAccessible(page);
    // Built-in roles are read-only.
    await page.getByRole("link", { name: /^ridm:owner/ }).click();
    await expect(page.getByLabel("Name")).toBeDisabled({ timeout: 10_000 });
  });

  test("groups: tree, subgroup, roles and members", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/groups/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Groups", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New group" }).click();
    await page.getByRole("dialog", { name: "New group" }).getByLabel("Name").fill(g);
    await page.getByRole("dialog", { name: "New group" }).getByRole("button", { name: "Create group" }).click();
    await page.waitForURL(/groups\/\?tenant=master&group=/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: g, level: 2 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Subgroup" }).click();
    const sub = page.getByRole("dialog", { name: "New group" });
    await expect(sub.getByLabel("Parent")).toHaveValue(/.+/);
    await sub.getByLabel("Name").fill("engineering");
    await sub.getByRole("button", { name: "Create group" }).click();
    await expect(page.getByRole("heading", { name: `${g} / engineering`, level: 2 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("tree").getByRole("link", { name: "engineering" })).toBeVisible();

    await page.getByLabel("Role to add").selectOption({ label: role });
    await page.getByRole("button", { name: "Add", exact: true }).click();
    await expect(page.getByRole("listitem").filter({ hasText: role })).toBeVisible({ timeout: 10_000 });
    await page.getByRole("button", { name: "Add member" }).click();
    await page.getByRole("combobox", { name: "Add member" }).fill(loadState().email);
    await page.getByRole("option", { name: loadState().email }).click();
    await expect(page.getByRole("link", { name: loadState().email })).toBeVisible({ timeout: 10_000 });
    await expectAccessible(page);

    // Moving a group under its own subgroup is not offered.
    await page.getByRole("tree").getByRole("link", { name: g, exact: true }).click();
    await expect(page.getByRole("heading", { name: g, level: 2 })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByLabel("Parent").locator("option", { hasText: "engineering" })).toHaveCount(0);
  });

  test("scopes and claim mappers", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/scopes/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Scopes", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("link", { name: /^openid/ }).click();
    await expect(page.getByText("standard", { exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("button", { name: "Delete scope" })).toBeHidden();
    await page.getByRole("button", { name: "New scope" }).click();
    const sd = page.getByRole("dialog", { name: "New scope" });
    await sd.getByLabel("Name").fill(scope);
    await sd.getByLabel("Description").fill("Read your orders");
    await sd.getByRole("button", { name: "Create scope" }).click();
    await page.waitForURL(/scopes\/\?tenant=master&scope=/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: scope, level: 2 })).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Claims").fill("orders");
    await page.keyboard.press("Enter");
    await page.getByRole("switch", { name: "Granted by default" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await expectAccessible(page);
    await page.reload();
    await expect(page.getByText("orders", { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("switch", { name: "Granted by default" })).toHaveAttribute("aria-checked", "true");

    await page.goto(`/console/claim-mappers/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Claim mappers", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New mapper" }).click();
    const md = page.getByRole("dialog", { name: "New claim mapper" });
    await md.getByLabel("Name", { exact: true }).fill(mapper);
    await md.getByLabel("Kind").selectOption("template");
    await md.getByLabel("Claim name").fill("display");
    await md.getByLabel("Template").fill("{{user.username}} of {{tenant.slug}}");
    await md.getByRole("button", { name: "Create mapper" }).click();
    await page.waitForURL(/claim-mappers\/\?tenant=master&mapper=/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { level: 2 }).filter({ hasText: mapper })).toContainText("tenant-wide", { timeout: 15_000 });
    // A template that does not compile is refused and the stored one comes back.
    await page.getByLabel("Template").fill("{{#if}}");
    await expect(page.getByRole("alert").filter({ hasText: /template|compile/i })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByLabel("Template")).toHaveValue("{{user.username}} of {{tenant.slug}}", { timeout: 10_000 });
    await page.getByRole("checkbox", { name: "userinfo" }).check();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await expectAccessible(page);
  });

  test("cleans up", async ({ page }) => {
    await consoleLogin(page, loadState());
    const remove = async (path: string, listName: RegExp, what: string) => {
      await page.goto(path);
      await page.getByRole("link", { name: listName }).first().click();
      await page.getByRole("button", { name: `Delete ${what}` }).first().click();
      await page.getByRole("dialog").getByRole("button", { name: `Delete ${what}` }).click();
      await page.waitForURL(new RegExp(`tenant=${TENANT}$`), { timeout: 15_000 });
    };
    await remove(`/console/claim-mappers/?tenant=${TENANT}`, new RegExp(mapper), "mapper");
    await remove(`/console/scopes/?tenant=${TENANT}`, new RegExp(scope), "scope");
    await remove(`/console/groups/?tenant=${TENANT}`, new RegExp(`^${g}$`), "group");
    await remove(`/console/roles/?tenant=${TENANT}`, new RegExp(`^${role}$`), "role");
    await remove(`/console/resource-servers/?tenant=${TENANT}`, new RegExp(`E2E API ${suffix}`), "resource server");
    await page.goto(`/console/groups/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Groups", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("tree").getByRole("link", { name: "engineering" })).toBeHidden();
  });
});
