import { expect, test, type Browser, type Page } from "@playwright/test";
import { clearTenantCache, expectAccessible, loadState, tenantId, tenantSql, TENANT } from "./helpers";

/**
 * The rest of the account console: the profile by the tenant's schema
 * (saved as it is edited, admin-only fields read-only), the sessions list
 * with another browser signed out from here, the connected applications
 * and the data page (the export downloads, deletion asks for the username).
 */

const SCHEMA = JSON.stringify([
  { name: "nickname", type: "string", label: "Nickname", order: 1 },
  { name: "badge", type: "string", label: "Badge", editable_by: "admin", order: 2 },
]);

/** Sign in through the tenant and land on `path`. */
async function signIn(page: Page, path: string) {
  const s = loadState();
  await page.goto(`${path}?tenant=${TENANT}`);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL(/\/login\//);
  await page.getByLabel("Email or username").fill(s.email);
  await page.getByLabel("Password", { exact: true }).fill(s.password);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL(new RegExp(`${path.replace(/\//g, "\\/")}(\\?.*)?$`), { timeout: 20_000 });
}

test.describe("account console: profile, sessions, applications and data", () => {
  test.describe.configure({ mode: "serial" });

  test.beforeAll(() => {
    const tid = tenantId();
    tenantSql(`INSERT INTO user_profile_schema (tenant_id, attributes) VALUES ('${tid}', '${SCHEMA}'::jsonb) ON CONFLICT (tenant_id) DO UPDATE SET attributes = EXCLUDED.attributes`);
    tenantSql(`UPDATE users SET attributes = '{"badge": "gold"}'::jsonb WHERE tenant_id = '${tid}' AND email = '${loadState().email}'`);
    clearTenantCache();
  });

  test.afterAll(() => {
    const tid = tenantId();
    tenantSql(`UPDATE user_profile_schema SET attributes = '[]'::jsonb WHERE tenant_id = '${tid}'`);
    tenantSql(`UPDATE users SET attributes = '{}'::jsonb WHERE tenant_id = '${tid}' AND email = '${loadState().email}'`);
    clearTenantCache();
  });

  test("edits the profile and the change is saved; admin-only fields stay read-only", async ({ page }) => {
    await signIn(page, "/account/");
    await expect(page.getByRole("heading", { name: "Profile", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByLabel("Username")).toBeDisabled();
    const badge = page.getByLabel("Badge");
    await expect(badge).toHaveValue("gold");
    await expect(badge).toBeDisabled();
    await expectAccessible(page);

    await page.getByLabel("Nickname").fill("Al");
    await expect(page.getByText(/^Saved$/)).toBeVisible({ timeout: 15_000 });
    await page.reload();
    await expect(page.getByLabel("Nickname")).toHaveValue("Al", { timeout: 15_000 });
    await expect(page.getByLabel("Badge")).toHaveValue("gold");

    const contact = page.getByRole("heading", { name: "Contact details" }).locator("..").locator("..");
    await expect(contact).toContainText(loadState().email);
    await expect(contact).toContainText("Verified");
  });

  test("lists the sessions and signs another browser out from here", async ({ page, browser }) => {
    await signIn(page, "/account/security/");
    await expect(page.getByRole("heading", { name: "Security", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "Password" })).toBeVisible();
    const list = page.getByRole("list", { name: "Where you are signed in" });
    await expect(list.getByText("This browser")).toHaveCount(1, { timeout: 15_000 });

    // Earlier specs left sessions behind: end them all but this one.
    const other = await secondBrowser(browser);
    await page.reload();
    await expect(page.getByRole("button", { name: "Sign out everywhere else" })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Sign out everywhere else" }).click();
    await expect(list.getByRole("listitem")).toHaveCount(1, { timeout: 15_000 });
    await other.page.reload();
    await expect(other.page.getByRole("heading", { name: "Manage your account" })).toBeVisible({ timeout: 15_000 });
    await other.context.close();

    // One more browser, ended on its own.
    const another = await secondBrowser(browser);
    await page.reload();
    await expect(list.getByRole("listitem")).toHaveCount(2, { timeout: 15_000 });
    await expectAccessible(page);
    await list.getByRole("button", { name: "Sign out" }).click();
    await expect(list.getByRole("listitem")).toHaveCount(1, { timeout: 15_000 });
    await another.page.reload();
    await expect(another.page.getByRole("heading", { name: "Manage your account" })).toBeVisible({ timeout: 15_000 });
    await another.context.close();
  });

  test("shows connected applications and the data page downloads the export", async ({ page }) => {
    await signIn(page, "/account/apps/");
    await expect(page.getByRole("heading", { name: "Applications", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "Connected applications" })).toBeVisible();
    await expectAccessible(page);

    await page.getByRole("link", { name: "Your data" }).click();
    await page.waitForURL(/\/account\/data\//);
    await expect(page.getByRole("heading", { name: "Your data", level: 1 })).toBeVisible();
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download" }).click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/^master-.*\.json$/);
    const body = JSON.parse((await (await file.createReadStream()).toArray()).join("")) as { user: { email: string }; audit_events: unknown[] };
    expect(body.user.email).toBe(loadState().email);
    expect(Array.isArray(body.audit_events)).toBe(true);

    await page.getByRole("button", { name: "Delete account" }).click();
    const dialog = page.getByRole("dialog", { name: "Delete your account" });
    await expect(dialog.getByRole("button", { name: "Delete account" })).toBeDisabled();
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Close" }).click();
  });
});

/** A second, signed-in account console in its own browser context. */
async function secondBrowser(browser: Browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signIn(page, "/account/security/");
  await expect(page.getByRole("heading", { name: "Security", level: 1 })).toBeVisible({ timeout: 15_000 });
  return { context, page };
}
