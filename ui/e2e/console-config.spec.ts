import { expect, test } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/** Tenant configuration export, plan preview and apply. */
test("export, preview a change, apply it, and revert", async ({ page }) => {
  await consoleLogin(page, loadState());
  await page.goto(`/console/config/?tenant=${TENANT}`);
  await expect(page.getByRole("heading", { name: "Export & import", level: 1 })).toBeVisible({ timeout: 15_000 });
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: /Download master/ }).click()]);
  expect(download.suggestedFilename()).toBe(`${TENANT}.ridm.json`);

  await page.getByRole("button", { name: "Load into the editor below" }).click();
  const editor = page.getByLabel("Configuration document");
  await expect(editor).toContainText('"format": "ridm.tenant/1"', { timeout: 15_000 });
  await page.getByRole("button", { name: "Preview changes" }).click();
  await expect(page.getByText("The document matches the tenant: nothing to do.")).toBeVisible({ timeout: 20_000 });
  await expectAccessible(page);

  const original = JSON.parse(await editor.inputValue()) as { tenant: { display_name: string } };
  const changed = { ...original, tenant: { ...original.tenant, display_name: "Master (renamed)" } };
  await editor.fill(JSON.stringify(changed, null, 2));
  await page.getByRole("button", { name: "Preview changes" }).click();
  await expect(page.getByRole("status").filter({ hasText: "1 update" })).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("display_name")).toBeVisible();
  await expect(page.locator("dd").filter({ hasText: "Master (renamed)" })).toBeVisible();
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByRole("heading", { name: "Applied" })).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole("status").filter({ hasText: "1 applied" })).toBeVisible();

  // Revert through the same path.
  await editor.fill(JSON.stringify(original, null, 2));
  await page.getByRole("button", { name: "Preview changes" }).click();
  await expect(page.getByRole("status").filter({ hasText: "1 update" })).toBeVisible({ timeout: 20_000 });
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByRole("heading", { name: "Applied" })).toBeVisible({ timeout: 20_000 });
  await page.reload();
  await expect(page.getByRole("button", { name: /Tenant: master/ })).toBeVisible({ timeout: 15_000 });
});
