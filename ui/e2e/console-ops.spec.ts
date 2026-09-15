import { expect, test } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState, TENANT, tenantSql } from "./helpers";

/** Signing keys, audit log, webhooks, IP rules and messaging. */
test.describe("operations", () => {
  const suffix = loadState().email.replace(/\D/g, "").slice(-9);

  // A template override left behind by a failed run would break the other
  // specs' emails (verification links), so drop it whatever happened.
  test.afterAll(() => {
    tenantSql(`DELETE FROM message_templates WHERE body_text LIKE '%from ${suffix}%'`);
  });

  test("keys: timeline, new pending key, activate, retire, revoke", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/keys/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Signing keys", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("list", { name: "Key timeline" })).toBeVisible();
    await expect(page.getByText("Master key", { exact: true })).toBeVisible();
    const before = await page.getByText("pending", { exact: true }).count();
    await page.getByRole("button", { name: "New key" }).click();
    await page.getByRole("dialog", { name: "New signing key" }).getByRole("button", { name: "Create key" }).click();
    await expect(page.getByText("pending", { exact: true })).toHaveCount(before + 1, { timeout: 15_000 });
    await expectAccessible(page);
    // The newest key is listed first: activate it, then retire it, then revoke it.
    const card = page.locator("section").filter({ has: page.getByText("pending", { exact: true }) }).first();
    await card.getByRole("button", { name: "Activate" }).click();
    await expect(page.getByText("active", { exact: true }).first()).toBeVisible({ timeout: 10_000 });
    const active = page.locator("section").filter({ has: page.getByRole("button", { name: "Retire" }) }).first();
    await active.getByRole("button", { name: "Retire" }).click();
    await expect(page.getByText("retiring", { exact: true }).first()).toBeVisible({ timeout: 10_000 });
    const retiring = page.locator("section").filter({ has: page.getByText("retiring", { exact: true }) }).first();
    await retiring.getByRole("button", { name: "Revoke" }).click();
    await expect(page.getByText("revoked", { exact: true }).first()).toBeVisible({ timeout: 10_000 });
    // Rotation leaves exactly one active key per algorithm.
    await page.getByRole("button", { name: "Rotate now" }).click();
    await expect(page.getByText("active", { exact: true })).toHaveCount(1, { timeout: 15_000 });
    await page.getByRole("button", { name: "Show public key (JWK)" }).first().click();
    await expect(page.getByLabel("Public JWK").first()).toContainText('"kty"');
  });

  test("audit: filter, expand, verify and export", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/audit/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Audit log", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: /signing_key/ }).first()).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Event").selectOption("signing_key.created");
    await page.getByRole("button", { name: "Apply filters" }).click();
    await expect(page.getByRole("button", { name: /^signing_key\.created/ }).first()).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: /^user\./ })).toHaveCount(0);
    await page.getByRole("button", { name: /^signing_key\.created/ }).first().click();
    await expect(page.getByLabel("Event details").first()).toContainText('"hash"');
    await page.getByRole("button", { name: "Verify chain" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Chain intact" })).toBeVisible({ timeout: 20_000 });
    await expectAccessible(page);
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "CSV" }).click()]);
    expect(download.suggestedFilename()).toBe(`audit-${TENANT}.csv`);
    await page.getByLabel("Chain").selectOption("global");
    await expect(page.getByRole("heading", { name: "Events" })).toBeVisible();
  });

  test("webhooks: create with a secret, edit, test ping, deliveries, delete", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/webhooks/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Webhooks", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New webhook" }).click();
    const dialog = page.getByRole("dialog", { name: "New webhook" });
    await dialog.getByLabel("Name").fill(`E2E hook ${suffix}`);
    await dialog.getByLabel("URL").fill("https://hooks.example.com/ridm");
    await dialog.getByRole("button", { name: "Create webhook" }).click();
    const reveal = page.getByRole("dialog", { name: `E2E hook ${suffix} created` });
    await expect(reveal.getByTestId("secret-value")).not.toBeEmpty({ timeout: 15_000 });
    await reveal.getByRole("button", { name: "I have stored it" }).click();
    await page.waitForURL(/webhooks\/\?tenant=master&webhook=/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: `E2E hook ${suffix}`, level: 2 })).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Events").fill("user.created");
    await page.keyboard.press("Enter");
    await page.getByLabel("Maximum attempts").fill("3");
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await page.getByRole("button", { name: "Send test ping" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Test delivery queued" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("listitem").filter({ hasText: "webhook.test" }).first()).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);
    await page.getByRole("button", { name: "Rotate secret" }).click();
    const rotated = page.getByRole("dialog", { name: "New signing secret" });
    await expect(rotated.getByTestId("secret-value")).not.toBeEmpty({ timeout: 10_000 });
    await rotated.getByRole("button", { name: "I have stored it" }).click();
    await page.getByRole("button", { name: "Delete webhook" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete webhook" }).click();
    await page.waitForURL(/webhooks\/\?tenant=master$/, { timeout: 15_000 });
    await expect(page.getByRole("link", { name: new RegExp(`E2E hook ${suffix}`) })).toBeHidden();
  });

  test("ip rules: add, change action, delete", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/ip-rules/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "IP rules", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Network (CIDR)").fill("203.0.113.0/24");
    await page.getByLabel("Description", { exact: true }).fill(`E2E ${suffix}`);
    await page.getByRole("button", { name: "Add rule" }).click();
    const row = page.getByRole("row").filter({ hasText: "203.0.113.0/24" });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await row.getByLabel("Action for 203.0.113.0/24").selectOption("allow");
    await expect(row.getByLabel("Action for 203.0.113.0/24")).toHaveValue("allow", { timeout: 10_000 });
    await expectAccessible(page);
    await page.reload();
    await expect(page.getByRole("row").filter({ hasText: "203.0.113.0/24" }).getByLabel("Action for 203.0.113.0/24")).toHaveValue("allow", { timeout: 15_000 });
    await page.getByRole("button", { name: "Delete rule 203.0.113.0/24" }).click();
    await expect(page.getByRole("row").filter({ hasText: "203.0.113.0/24" })).toBeHidden({ timeout: 10_000 });
  });

  test("messaging: template override with live preview, test send, log", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/messaging/?tenant=${TENANT}&tab=templates`);
    await expect(page.getByRole("heading", { name: "Messaging", level: 1 })).toBeVisible({ timeout: 15_000 });
    // Pick an event no other spec relies on.
    await page.getByLabel("Event").selectOption({ label: "password_changed" });
    await expect(page.getByText("Built-in", { exact: true })).toBeVisible({ timeout: 15_000 });
    const text = page.getByLabel("Text body");
    await expect(text).not.toBeEmpty({ timeout: 15_000 });
    await text.fill(`Hello {{user.username}} from ${suffix}`);
    await expect(page.getByText(`from ${suffix}`)).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Save override" }).click();
    await expect(page.getByText("Tenant override")).toBeVisible({ timeout: 10_000 });
    // The HTML preview is a fully sandboxed frame axe cannot enter.
    await expectAccessible(page, { iframes: false });
    await page.getByRole("button", { name: "Reset to built-in" }).click();
    await expect(page.getByText("Built-in", { exact: true })).toBeVisible({ timeout: 10_000 });

    await page.getByRole("navigation", { name: "Messaging sections" }).getByRole("link", { name: "Email" }).click();
    await expect(page.getByRole("heading", { name: "Provider" })).toBeVisible();
    await page.getByLabel("Send a test email to").fill(`test-${suffix}@example.com`);
    await page.getByRole("button", { name: "Send test" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Sent to" })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("navigation", { name: "Messaging sections" }).getByRole("link", { name: "Delivery log" }).click();
    await expect(page.getByText(`test-${suffix}@example.com`)).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);
  });
});
