import { expect, test } from "@playwright/test";
import { API, authorizeUrl, clearTenantCache, consoleLogin, expectAccessible, finishAuthorization, loadState, t, tenantId, tenantSql, TENANT } from "./helpers";

/**
 * SAML identity provider upstream (Phase 13.2), with the tenant as its own
 * upstream: an administrator adds a SAML provider from the tenant's IdP
 * metadata URL and registers rIDM's SP metadata as a service provider in
 * the same tenant. The login page then offers "Continue with Corp SAML",
 * whose round trip is a real browser posting a signed response to the
 * assertion consumer service; the account is linked by verified email.
 */

const ALIAS = "samlself";
const NAME = "Corp SAML";
const SP_NAME = "rIDM as its own SP";
const SP_METADATA = `${API}${t(`/broker/${ALIAS}/saml/metadata`)}`;

test.describe("SAML identity provider upstream", () => {
  test.describe.configure({ mode: "serial" });

  test.afterAll(() => {
    const tid = tenantId();
    tenantSql(`DELETE FROM identity_providers WHERE tenant_id = '${tid}' AND alias = '${ALIAS}'`);
    tenantSql(`DELETE FROM clients WHERE tenant_id = '${tid}' AND client_type = 'saml' AND name = '${SP_NAME}'`);
    clearTenantCache();
  });

  test("an administrator adds a SAML provider from its metadata URL", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/identity-providers/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Identity providers", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New provider" }).click();
    const dialog = page.getByRole("dialog", { name: "New identity provider" });
    await dialog.getByLabel("Preset").selectOption("saml");
    await dialog.getByLabel("Alias").fill(ALIAS);
    await dialog.getByLabel("Display name").fill(NAME);
    await dialog.getByLabel("Metadata URL").fill(`${API}${t("/saml/metadata")}`);
    await expect(dialog.getByLabel("Client ID")).toHaveCount(0);
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Create provider" }).click();
    await expect(page.getByRole("heading", { name: NAME, level: 2 })).toBeVisible({ timeout: 15_000 });

    // What the IdP is given, and what was read from its metadata.
    const details = page.locator("section").filter({ has: page.getByRole("heading", { name: "Service provider details" }) });
    await expect(details.getByText(SP_METADATA)).toBeVisible();
    await expect(details.getByText(`${API}${t(`/broker/${ALIAS}/saml/acs`)}`)).toBeVisible();
    await expect(page.getByLabel("Entity ID", { exact: true })).toHaveValue(`${API}/t/${TENANT}`);
    await expect(page.getByLabel("Single sign-on URL")).toHaveValue(`${API}${t("/saml/sso")}`);
    await expect(page.getByLabel("NameID format")).toHaveValue("persistent");
    await expect(page.getByLabel("Token endpoint", { exact: true })).toHaveCount(0);

    // Edits save on their own; a refresh re-reads the metadata.
    await page.getByRole("switch", { name: "Force authentication" }).click();
    await expect(page.getByText(/^Saved$/)).toBeVisible({ timeout: 15_000 });
    await page.getByRole("switch", { name: "Force authentication" }).click();
    await page.getByRole("button", { name: "Refresh now" }).click();
    await expect(page.getByText(/^Last read /)).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);
  });

  test("rIDM's SP metadata registers it as a service provider", async ({ page }) => {
    const res = await fetch(SP_METADATA);
    expect(res.ok).toBeTruthy();
    const metadata = await res.text();
    await consoleLogin(page, loadState());
    await page.goto(`/console/saml/?tenant=${TENANT}`);
    await page.getByRole("button", { name: "New service provider" }).click();
    const dialog = page.getByRole("dialog", { name: "New service provider" });
    await dialog.getByLabel("Metadata").fill(metadata);
    await dialog.getByRole("button", { name: "Read metadata" }).click();
    await expect(dialog.getByLabel("Entity ID")).toHaveValue(SP_METADATA, { timeout: 15_000 });
    await dialog.getByLabel("Name").fill(SP_NAME);
    await dialog.getByRole("button", { name: "Create service provider" }).click();
    await expect(page.getByRole("heading", { name: SP_NAME, level: 2 })).toBeVisible({ timeout: 15_000 });
  });

  test("the login page offers it and signs the user in through it", async ({ page }) => {
    const s = loadState();
    await page.goto(authorizeUrl(s));
    await page.waitForURL(/\/login\//);
    const flow = new URL(page.url()).searchParams.get("flow");
    const button = page.getByRole("button", { name: `Continue with ${NAME}` });
    await expect(button).toBeVisible({ timeout: 15_000 });
    await button.click();
    // The upstream is the same tenant as a SAML IdP: its own login page, for
    // the service provider registered above.
    await page.waitForURL((u) => u.pathname.endsWith("/login/") && u.searchParams.get("flow") !== flow, { timeout: 20_000 });
    await expect(page.getByText(`to continue to ${SP_NAME}`)).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Email or username").fill(s.email);
    await page.getByLabel("Password", { exact: true }).fill(s.password);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    // The IdP posts the signed response; the assertion consumer service
    // signs the original flow in and sends the browser back to it.
    await page.waitForURL((u) => u.searchParams.get("flow") === flow, { timeout: 20_000 });
    await finishAuthorization(page);
    expect(new URL(page.url()).searchParams.get("code")).toBeTruthy();

    await page.goto(`/account/security/?tenant=${TENANT}`);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.waitForURL(/\/account\/security\//, { timeout: 20_000 });
    await expect(page.getByRole("list", { name: "Linked accounts" })).toContainText(NAME, { timeout: 15_000 });
  });
});
