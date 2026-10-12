import { expect, test } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState } from "./helpers";

/**
 * Settings → Appearance: a colour preset fills both theme colours and the
 * live preview follows; the light/dark policy reaches the preview and the
 * console itself; turning the person's switch off removes it.
 */
test.describe("tenant appearance", () => {
  // A tenant of its own, so the master tenant other specs rely on keeps its defaults.
  const slug = `e2e-look-${loadState().email.replace(/\D/g, "").slice(-8)}`;

  test("presets, policy and the switch", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto("/console/tenants/?tenant=master");
    await page.getByRole("button", { name: "New tenant" }).click();
    const dialog = page.getByRole("dialog", { name: "New tenant" });
    await dialog.getByLabel("Slug").fill(slug);
    await dialog.getByLabel("Display name").fill("Looks Co");
    await dialog.getByRole("button", { name: "Create tenant" }).click();
    await page.waitForURL(new RegExp(`/console/settings/\\?tenant=${slug}$`));
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible({ timeout: 15_000 });

    // Defaults: Signal v2, follow the device, the switch shown.
    await expect(page.getByRole("radio", { name: /Signal v2/ })).toHaveAttribute("aria-checked", "true");
    await expect(page.getByRole("radio", { name: "Follow each person's device" })).toBeChecked();
    await expect(page.getByRole("group", { name: "Theme", exact: true }).first()).toBeVisible();

    // A preset fills both colours, the shades and checks appear, and the real
    // login page in the preview takes the primary colour.
    await page.getByRole("radio", { name: "Ocean & coral" }).click();
    await expect(page.getByLabel("Primary colour", { exact: true })).toHaveValue("#0f766e");
    await expect(page.getByLabel("Contrast colour", { exact: true })).toHaveValue("#c2410c");
    await expect(page.getByRole("list", { name: "Readability checks" }).getByRole("listitem")).toHaveCount(5);
    const preview = page.frameLocator('iframe[title="Login page preview"]');
    await expect(preview.getByRole("heading", { name: "Sign in" })).toBeVisible({ timeout: 20_000 });
    await expect
      .poll(async () => preview.getByRole("button", { name: "Continue", exact: true }).evaluate((el) => getComputedStyle(el).backgroundColor), { timeout: 10_000 })
      .toBe("rgb(15, 118, 110)");

    // The policy: always dark reaches the preview at once.
    await page.getByRole("radio", { name: "Always dark" }).check();
    await expect(preview.locator("html")).toHaveAttribute("data-theme", "dark", { timeout: 10_000 });
    await page.getByRole("switch", { name: "People can switch between light and dark" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });

    // Stored: a fresh load of the console, administering this tenant, is dark
    // and offers no switch; the preset is still selected.
    await page.reload();
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark", { timeout: 10_000 });
    await expect(page.getByRole("group", { name: "Theme", exact: true })).toHaveCount(0);
    await expect(page.getByRole("radio", { name: "Ocean & coral" })).toHaveAttribute("aria-checked", "true");
    await expectAccessible(page);

    // Back to the device's choice with the switch on: the attribute goes away.
    await page.getByRole("radio", { name: "Follow each person's device" }).check();
    await page.getByRole("switch", { name: "People can switch between light and dark" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await page.reload();
    await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/, { timeout: 10_000 });
    await expect(page.getByRole("group", { name: "Theme", exact: true }).first()).toBeVisible();

    // What the API refuses never sticks: a word is not a colour.
    await page.getByLabel("Primary colour", { exact: true }).fill("tomato");
    await expect(page.getByRole("alert").filter({ hasText: /not a CSS colour/ })).toBeVisible({ timeout: 10_000 });
  });
});
