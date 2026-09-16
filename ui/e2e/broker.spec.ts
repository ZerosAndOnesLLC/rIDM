import { expect, test, type Page } from "@playwright/test";
import { API, authorizeUrl, clearTenantCache, consoleLogin, expectAccessible, finishAuthorization, loadState, t, tenantId, tenantSql, TENANT } from "./helpers";

/**
 * Identity brokering, with rIDM as its own upstream provider: a confidential
 * client registered in the tenant plays the "upstream" application. An
 * administrator adds the provider in the console (discovered from the
 * issuer), the login page offers "Continue with rIDM itself" and signs the
 * user in through it (the upstream sign-in is the ordinary password login
 * plus the consent screen; the account is linked by verified email), the
 * account console unlinks and links it again, the user detail lists the
 * identity, and the provider is deleted.
 */

const ISSUER = `${API}/t/${TENANT}`;
const ALIAS = "self";
const NAME = "rIDM itself";

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

test.describe("identity brokering", () => {
  test.describe.configure({ mode: "serial" });
  let clientId = "";
  let clientSecret = "";

  test.beforeAll(async () => {
    const res = await fetch(`${API}${t("/register")}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Upstream rIDM",
        redirect_uris: [`${ISSUER}/broker/${ALIAS}/callback`],
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["authorization_code"],
        response_types: ["code"],
      }),
    });
    if (!res.ok) throw new Error(`client registration failed: ${res.status} ${await res.text()}`);
    const body = (await res.json()) as { client_id: string; client_secret: string };
    clientId = body.client_id;
    clientSecret = body.client_secret;
  });

  test.afterAll(() => {
    const tid = tenantId();
    tenantSql(`DELETE FROM identity_providers WHERE tenant_id = '${tid}' AND alias = '${ALIAS}'`);
    if (clientId) tenantSql(`DELETE FROM clients WHERE tenant_id = '${tid}' AND client_id = '${clientId}'`);
    clearTenantCache();
  });

  test("an administrator adds the provider in the console", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/identity-providers/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Identity providers", level: 1 })).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);
    await page.getByRole("button", { name: "New provider" }).click();
    const dialog = page.getByRole("dialog", { name: "New identity provider" });
    await dialog.getByLabel("Alias").fill(ALIAS);
    await dialog.getByLabel("Display name").fill(NAME);
    await dialog.getByLabel("Issuer").fill(ISSUER);
    await dialog.getByLabel("Client ID").fill(clientId);
    await dialog.getByLabel("Client secret").fill(clientSecret);
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Create provider" }).click();
    await expect(page.getByRole("heading", { name: NAME, level: 2 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(`${ISSUER}/broker/${ALIAS}/callback`)).toBeVisible();
    await expect(page.getByLabel("Token endpoint", { exact: true })).toHaveValue(`${ISSUER}/token`);
    await expect(page.getByText("A secret is stored.")).toBeVisible();
    // The provider vouches for its addresses (its own users verified them).
    await page.getByRole("switch", { name: "Trust the provider's email addresses" }).click();
    await expect(page.getByText(/^Saved$/)).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);
  });

  test("the login page offers it and signs the user in through it", async ({ page }) => {
    const s = loadState();
    await page.goto(authorizeUrl(s));
    await page.waitForURL(/\/login\//);
    const flow = new URL(page.url()).searchParams.get("flow");
    await expect(page.getByRole("button", { name: `Continue with ${NAME}` })).toBeVisible({ timeout: 15_000 });
    await page.waitForLoadState("networkidle");
    await expectAccessible(page);
    await page.getByRole("button", { name: `Continue with ${NAME}` }).click();
    // The upstream is rIDM itself: its own login page for the "Upstream rIDM" client.
    await page.waitForURL(/\/login\//, { timeout: 20_000 });
    await expect(page.getByText("to continue to Upstream rIDM")).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Email or username").fill(s.email);
    await page.getByLabel("Password", { exact: true }).fill(s.password);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.waitForURL(/\/consent\//, { timeout: 20_000 });
    await page.getByRole("button", { name: "Allow" }).click();
    // The upstream finishes, the callback signs the original flow in and
    // sends the browser back to it (its own consent page for the app).
    await page.waitForURL((u) => u.searchParams.get("flow") === flow, { timeout: 20_000 });
    await finishAuthorization(page);
    const url = new URL(page.url());
    expect(url.searchParams.get("code")).toBeTruthy();

    // The identity is now linked to the account.
    await page.goto(`/account/security/?tenant=${TENANT}`);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.waitForURL(/\/account\/security\//, { timeout: 20_000 });
    const linked = page.getByRole("list", { name: "Linked accounts" });
    await expect(linked).toContainText(NAME, { timeout: 15_000 });
    await expect(linked).toContainText(s.email);
  });

  test("the account console unlinks and links it again", async ({ page }) => {
    await signInAccount(page, "/account/security/");
    const card = page.getByRole("heading", { name: "Linked accounts" }).locator("..").locator("..");
    await expect(card.getByRole("button", { name: "Unlink" })).toBeVisible({ timeout: 15_000 });
    await card.getByRole("button", { name: "Unlink" }).click();
    await page.getByRole("dialog", { name: `Unlink ${NAME}?` }).getByRole("button", { name: "Unlink" }).click();
    await expect(card.getByRole("button", { name: `Link ${NAME}` })).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);

    // Linking goes through the provider (already signed in there) and comes back.
    await card.getByRole("button", { name: `Link ${NAME}` }).click();
    await page.waitForURL(/\/account\/security\/\?.*linked=1/, { timeout: 20_000 });
    await expect(page.getByText("The account was linked.")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("list", { name: "Linked accounts" })).toContainText(NAME);
  });

  test("the user detail lists the identity and the provider is deleted", async ({ page }) => {
    const tid = tenantId();
    const userId = tenantSql(`SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${loadState().email}'`);
    await consoleLogin(page, loadState());
    await page.goto(`/console/users/?tenant=${TENANT}&user=${userId}`);
    await page.getByRole("navigation", { name: "User sections" }).getByRole("link", { name: "Password & credentials" }).click();
    const list = page.getByRole("list", { name: "Linked identities" });
    await expect(list).toContainText(NAME, { timeout: 15_000 });
    await expect(list).toContainText(ALIAS);
    await list.getByRole("button", { name: "Unlink" }).click();
    await expect(page.getByText("No upstream identity is linked.")).toBeVisible({ timeout: 15_000 });

    await page.goto(`/console/identity-providers/?tenant=${TENANT}`);
    await page.getByRole("link", { name: new RegExp(NAME) }).click();
    await expect(page.getByRole("heading", { name: NAME, level: 2 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Delete identity provider" }).click();
    await page.getByRole("dialog", { name: "Delete this identity provider?" }).getByRole("button", { name: "Delete identity provider" }).click();
    await expect(page.getByText("No providers yet.")).toBeVisible({ timeout: 15_000 });
  });
});
