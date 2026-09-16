import { expect, test, type Page } from "@playwright/test";
import { API, expectAccessible, loadState, TENANT, tenantId, tenantSql } from "./helpers";

/**
 * Personal access tokens: minted in the account console (shown once), used
 * as a bearer on the account API, listed on the user detail in the admin
 * console, revoked from the account console, then refused.
 */

async function signInAccount(page: Page, path: string) {
  const s = loadState();
  await page.goto(`${path}?tenant=${TENANT}`);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL(/\/login\//);
  await page.getByLabel("Email or username").fill(s.email);
  await page.getByLabel("Password", { exact: true }).fill(s.password);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL(new RegExp(`${path.replace(/\//g, "\\/")}(\\?.*)?$`), { timeout: 20_000 });
}

test.describe("personal access tokens", () => {
  test.describe.configure({ mode: "serial" });
  const name = `e2e-token-${loadState().email.replace(/\D/g, "").slice(-6)}`;
  let token = "";

  test.afterAll(() => {
    const tid = tenantId();
    tenantSql(`DELETE FROM personal_access_tokens WHERE tenant_id = '${tid}' AND name = '${name}'`);
  });

  test("a token is minted once, works as a bearer and is revoked", async ({ page }) => {
    await signInAccount(page, "/account/security/");
    await expect(page.getByRole("heading", { name: "Personal access tokens" })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New token" }).click();
    const dialog = page.getByRole("dialog", { name: "New token" });
    await dialog.getByLabel("Name").fill(name);
    await expect(dialog.getByRole("checkbox", { name: "Act on my account (the account API)" })).toBeChecked();
    await dialog.getByRole("checkbox", { name: "ridm:users:read" }).check();
    await dialog.getByLabel("Expires in (days)").fill("7");
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Create token" }).click();
    const minted = page.getByRole("dialog", { name: "Your new token" });
    await expect(minted).toBeVisible({ timeout: 15_000 });
    token = (await minted.getByTestId("secret-value").textContent())?.trim() ?? "";
    expect(token).toMatch(/^rpat_[A-Za-z0-9_-]{40,}$/);
    await minted.getByRole("button", { name: "I have saved it" }).click();
    const list = page.getByRole("list", { name: "Personal access tokens" });
    await expect(list).toContainText(name);
    await expect(list).toContainText("ridm:users:read");
    await expectAccessible(page);

    // The token acts as the user on the account API and the admin API.
    const me = await fetch(`${API}/t/${TENANT}/account/me`, { headers: { Authorization: `Bearer ${token}` } });
    expect(me.status).toBe(200);
    expect(((await me.json()) as { email: string }).email).toBe(loadState().email);
    const users = await fetch(`${API}/admin/tenants/${TENANT}/users?limit=1`, { headers: { Authorization: `Bearer ${token}` } });
    expect(users.status).toBe(200);
    const forbidden = await fetch(`${API}/admin/tenants/${TENANT}/webhooks`, { headers: { Authorization: `Bearer ${token}` } });
    expect(forbidden.status).toBe(403);

    // Revoked from the console: refused at once.
    await list.getByRole("button", { name: "Revoke" }).first().click();
    await page.getByRole("dialog", { name: `Revoke ${name}?` }).getByRole("button", { name: "Revoke" }).click();
    await expect(page.getByText("No personal access tokens.")).toBeVisible({ timeout: 15_000 });
    const after = await fetch(`${API}/t/${TENANT}/account/me`, { headers: { Authorization: `Bearer ${token}` } });
    expect(after.status).toBe(401);
  });
});
