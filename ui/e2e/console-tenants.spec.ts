import { expect, test, type Page } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState } from "./helpers";

/**
 * Tenants list and creation, the settings page saving as you go, the
 * branding editor driving the live login-page preview, and deletion.
 */
test.describe("tenants and settings", () => {
  // Stable across worker restarts within one run, unique per global setup.
  const slug = `e2e-${loadState().email.replace(/\D/g, "").slice(-9)}`;

  async function openSettings(page: Page) {
    await page.goto(`/console/settings/?tenant=${slug}`);
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible({ timeout: 15_000 });
  }

  test("lists tenants and creates one", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.getByRole("navigation", { name: "Console" }).getByRole("link", { name: "Tenants" }).click();
    await expect(page.getByRole("heading", { name: "Tenants", level: 1 })).toBeVisible();
    await expect(page.getByRole("row", { name: /master/ })).toBeVisible();
    await expectAccessible(page);

    await page.getByRole("button", { name: "New tenant" }).click();
    const dialog = page.getByRole("dialog", { name: "New tenant" });
    await dialog.getByLabel("Slug").fill("Bad Slug");
    await dialog.getByLabel("Display name").fill("E2E Tenant");
    await dialog.getByRole("button", { name: "Create tenant" }).click();
    await expect(dialog.getByRole("alert")).toContainText("lowercase");
    await dialog.getByLabel("Slug").fill(slug);
    await dialog.getByRole("button", { name: "Create tenant" }).click();

    // Lands on the new tenant's settings.
    await page.waitForURL(new RegExp(`/console/settings/\\?tenant=${slug}$`));
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();
    await expect(page.getByText(`E2E Tenant · ${slug}`)).toBeVisible();
    await expect(page.getByRole("button", { name: /Tenant: / })).toContainText(slug);
    await expectAccessible(page);
  });

  test("settings save as you go and survive a reload", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openSettings(page);

    await page.getByLabel("Display name").fill("E2E Tenant Renamed");
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });

    const magic = page.getByRole("switch", { name: "Magic link" });
    await expect(magic).toHaveAttribute("aria-checked", "false");
    await magic.click();
    await page.getByLabel("Minimum length").fill("14");
    await page.getByRole("combobox", { name: "Two-step verification" }).selectOption("required_for_roles");
    await page.getByLabel("Roles that require it").fill("finance");
    await page.keyboard.press("Enter");
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("status").filter({ hasText: /Unsaved|Saving/ })).toBeHidden({ timeout: 10_000 });

    await page.reload();
    await expect(page.getByLabel("Display name")).toHaveValue("E2E Tenant Renamed", { timeout: 15_000 });
    await expect(page.getByRole("switch", { name: "Magic link" })).toHaveAttribute("aria-checked", "true");
    await expect(page.getByLabel("Minimum length")).toHaveValue("14");
    await expect(page.getByRole("combobox", { name: "Two-step verification" })).toHaveValue("required_for_roles");
    await expect(page.getByText("finance", { exact: true })).toBeVisible();

    // The API refuses what it cannot store and the page says so.
    await page.getByLabel("Terms of service URL").fill("not a url");
    await expect(page.getByText("Enter an http(s) URL.")).toBeVisible();
  });

  test("branding changes show in the live login-page preview", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openSettings(page);
    const preview = page.frameLocator('iframe[title="Login page preview"]');
    await expect(preview.getByRole("heading", { name: "Sign in" })).toBeVisible({ timeout: 20_000 });

    await page.getByLabel("Primary colour", { exact: true }).fill("#8b0000");
    await expect
      .poll(async () => preview.getByRole("button", { name: "Continue" }).evaluate((el) => getComputedStyle(el).backgroundColor), { timeout: 10_000 })
      .toBe("rgb(139, 0, 0)");
    await page.getByRole("button", { name: "Add link" }).click();
    await page.getByLabel("Link 1 label").fill("Status");
    await page.getByLabel("Link 1 URL").fill("https://status.example.com");
    await expect(preview.getByRole("link", { name: "Status" })).toBeVisible({ timeout: 10_000 });
    await page.getByLabel("Display name").fill("Preview Co");
    await expect(preview.getByText("Preview Co")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });

    // Stored: a fresh load of the preview carries the colour.
    await page.reload();
    await expect(preview.getByRole("heading", { name: "Sign in" })).toBeVisible({ timeout: 20_000 });
    await expect
      .poll(async () => preview.getByRole("button", { name: "Continue" }).evaluate((el) => getComputedStyle(el).backgroundColor), { timeout: 10_000 })
      .toBe("rgb(139, 0, 0)");
    await expectAccessible(page);
  });

  test("deletes the tenant after typing its slug", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openSettings(page);
    await page.getByRole("button", { name: "Delete tenant…" }).click();
    const dialog = page.getByRole("dialog", { name: `Delete ${slug}?` });
    await expect(dialog.getByRole("button", { name: "Delete tenant" })).toBeDisabled();
    await dialog.getByLabel("Tenant slug").fill(slug);
    await dialog.getByRole("button", { name: "Delete tenant" }).click();
    await page.waitForURL(/\/console\/tenants\/\?tenant=master$/);
    await expect(page.getByRole("heading", { name: "Tenants", level: 1 })).toBeVisible();
    await expect(page.getByRole("row", { name: new RegExp(slug) })).toBeHidden();
  });
});
