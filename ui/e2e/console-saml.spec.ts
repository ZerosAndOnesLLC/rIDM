import { expect, test } from "@playwright/test";
import { API, consoleLogin, expectAccessible, loadState, t, TENANT } from "./helpers";

/**
 * SAML identity provider (Phase 13.1): the console shows what to give a
 * service provider and registers one; the registered SP then gets a real
 * browser sign-in, its assertion consumer service stood in for by a
 * Playwright route that captures the posted response.
 */
test.describe("SAML identity provider", () => {
  const state = loadState();
  const suffix = state.email.replace(/\D/g, "").slice(-9);
  const entity = `https://sp-${suffix}.example`;
  const acs = `${entity}/acs`;

  test("register a service provider and sign in to it", async ({ page }) => {
    await consoleLogin(page, state);
    await page.goto(`/console/saml/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "SAML", level: 1 })).toBeVisible({ timeout: 15_000 });
    const idp = page.locator("section").filter({ has: page.getByRole("heading", { name: "Identity provider" }) });
    await expect(idp.getByText(`${API}${t("/saml/metadata")}`)).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("active", { exact: true }).first()).toBeVisible();
    await expectAccessible(page);

    // Register by hand: name, entity ID, consumer URL.
    await page.getByRole("button", { name: "New service provider" }).click();
    const dialog = page.getByRole("dialog", { name: "New service provider" });
    await dialog.getByLabel("Name").fill(`E2E SP ${suffix}`);
    await dialog.getByLabel("Entity ID").fill(entity);
    await dialog.getByLabel("Assertion consumer service URL").fill(acs);
    await dialog.getByRole("button", { name: "Create service provider" }).click();
    await expect(page.getByRole("heading", { name: `E2E SP ${suffix}`, level: 2 })).toBeVisible({ timeout: 15_000 });
    await expect(page).toHaveURL(/[?&]sp=/);

    // Edits save on their own: email NameIDs, one mapped attribute, and
    // IdP-initiated sign-in, which shows the launcher link.
    await page.getByLabel("NameID format").selectOption("email");
    await page.getByRole("button", { name: "Add attribute" }).click();
    await page.getByLabel("Claim 1").fill("email");
    await page.getByLabel("Attribute name 1").fill("mail");
    await page.getByRole("switch", { name: "Allow IdP-initiated sign-in" }).click();
    await expect(page.getByText("Saved")).toBeVisible({ timeout: 15_000 });
    const link = page.getByRole("button", { name: "Copy sign-in link" });
    await expect(link).toBeVisible();
    await expectAccessible(page);

    // The launcher link signs in (the console session is this tenant's) and
    // posts a response to the SP.
    const initUrl = (await page.locator("code").filter({ hasText: "/saml/init?sp=" }).textContent())!;
    let posted: string | null = null;
    await page.route(`${acs}**`, async (route) => {
      posted = route.request().postData();
      await route.fulfill({ status: 200, contentType: "text/html", body: "<!DOCTYPE html><title>SP</title><h1>Signed in</h1>" });
    });
    await page.goto(initUrl);
    await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible({ timeout: 15_000 });
    expect(posted).toBeTruthy();
    const form = new URLSearchParams(posted!);
    const xml = Buffer.from(form.get("SAMLResponse")!, "base64").toString("utf8");
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:status:Success");
    expect(xml).toContain(`<saml:Audience>${entity}</saml:Audience>`);
    expect(xml).toContain(`>${state.email}</saml:NameID>`);
    expect(xml).toContain('Name="mail"');
    await page.unroute(`${acs}**`);

    // And it goes away again.
    await page.goto(`/console/saml/?tenant=${TENANT}`);
    await page.getByRole("link", { name: new RegExp(`E2E SP ${suffix}`) }).click();
    await page.getByRole("button", { name: "Delete service provider" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete service provider" }).click();
    await expect(page.getByRole("link", { name: new RegExp(`E2E SP ${suffix}`) })).toHaveCount(0, { timeout: 15_000 });
  });
});
