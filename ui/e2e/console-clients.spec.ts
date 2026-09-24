import { expect, test, type Page } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/**
 * Clients: the table, the creation wizard with its reveal-once secret,
 * the detail page saving as you go, secrets and service accounts, the
 * playground running a real sign-in, and deletion.
 */
test.describe("clients", () => {
  const suffix = loadState().email.replace(/\D/g, "").slice(-9);
  const webName = `E2E Web ${suffix}`;
  const spaName = `E2E SPA ${suffix}`;

  async function openClients(page: Page) {
    await page.goto(`/console/clients/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Clients", level: 1 })).toBeVisible({ timeout: 15_000 });
  }
  async function openDetail(page: Page, name: string) {
    await openClients(page);
    await page.getByLabel("Search clients").fill(name);
    await page.getByRole("link", { name, exact: true }).click();
    await expect(page.getByRole("heading", { name, level: 1 })).toBeVisible({ timeout: 15_000 });
  }

  test("creates a confidential client through the wizard and reveals its secret once", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openClients(page);
    await expectAccessible(page);
    await page.getByRole("button", { name: "New client" }).click();
    const dialog = page.getByRole("dialog", { name: "New client" });
    await dialog.getByRole("radio", { name: /Web application/ }).check();
    await dialog.getByLabel("Name").fill(webName);
    await dialog.getByLabel("Client ID").fill("bad id!");
    await expect(dialog.getByRole("button", { name: "Next" })).toBeDisabled();
    await dialog.getByLabel("Client ID").fill(`e2e-web-${suffix}`);
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Next" }).click();

    // Grants: the type's defaults are preselected.
    await expect(dialog.getByRole("checkbox", { name: "Authorization code" })).toBeChecked();
    await expect(dialog.getByRole("combobox", { name: "Client authentication" })).toHaveValue("client_secret_basic");
    await dialog.getByRole("checkbox", { name: "Client credentials" }).check();
    await dialog.getByRole("button", { name: "Next" }).click();

    // URIs: a redirect URI is required for the authorization code grant.
    await expect(dialog.getByRole("button", { name: "Next" })).toBeDisabled();
    await dialog.getByLabel("Redirect URIs", { exact: true }).fill("https://app.example.com/callback");
    await page.keyboard.press("Enter");
    await dialog.getByRole("button", { name: "Next" }).click();

    await expect(dialog.getByRole("checkbox", { name: "openid" })).toBeChecked();
    await dialog.getByRole("checkbox", { name: "urn:ridm:admin" }).check();
    await dialog.getByRole("button", { name: "Create client" }).click();

    const reveal = page.getByRole("dialog", { name: `${webName} created` });
    await expect(reveal).toBeVisible({ timeout: 15_000 });
    const values = reveal.getByTestId("secret-value");
    await expect(values.nth(0)).toHaveText(`e2e-web-${suffix}`);
    await expect(values.nth(1)).not.toBeEmpty();
    await expectAccessible(page);
    await reveal.getByRole("button", { name: "I have stored it" }).click();

    await expect(page.getByRole("heading", { name: webName, level: 1 })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("Web application")).toBeVisible();
    await expect(page.getByRole("checkbox", { name: "Client credentials" })).toBeChecked();
    await expect(page.getByRole("checkbox", { name: /urn:ridm:admin/ })).toBeChecked();
    await expect(page.getByRole("row", { name: /Current/ })).toBeVisible();
    await expectAccessible(page);
  });

  test("detail saves as you go, rotates secrets and enables a service account", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openDetail(page, webName);

    await page.getByLabel("Description").fill("Customer portal backend");
    await page.getByLabel("Post-logout redirect URIs").fill("https://app.example.com/");
    await page.keyboard.press("Enter");
    await page.getByRole("switch", { name: "Ask users for consent" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 10_000 });
    await page.reload();
    await expect(page.getByLabel("Description")).toHaveValue("Customer portal backend", { timeout: 15_000 });
    await expect(page.getByText("https://app.example.com/", { exact: true })).toBeVisible();
    await expect(page.getByRole("switch", { name: "Ask users for consent" })).toHaveAttribute("aria-checked", "false");

    // A rule the API enforces shows up as the save error and the page reloads.
    await page.getByRole("combobox", { name: "Client authentication" }).selectOption("none");
    await expect(page.getByRole("alert").filter({ hasText: /client_credentials|authentication/ })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("combobox", { name: "Client authentication" })).toHaveValue("client_secret_basic", { timeout: 10_000 });

    // Rotate: the new secret is revealed once and both are listed.
    await page.getByRole("combobox", { name: "Grace period" }).selectOption("3600");
    await page.getByRole("button", { name: "Rotate secret" }).click();
    const reveal = page.getByRole("dialog", { name: "New client secret" });
    await expect(reveal.getByTestId("secret-value")).not.toBeEmpty({ timeout: 10_000 });
    await reveal.getByRole("button", { name: "I have stored it" }).click();
    await expect(page.getByRole("row", { name: /Retiring/ })).toBeVisible();
    await page.getByRole("row", { name: /Retiring/ }).getByRole("button", { name: "Revoke" }).click();
    await expect(page.getByRole("row", { name: /Retiring/ })).toBeHidden({ timeout: 10_000 });

    await page.getByRole("button", { name: "Enable service account" }).click();
    await expect(page.getByRole("link", { name: `svc-e2e-web-${suffix}` })).toBeVisible({ timeout: 10_000 });

    await page.getByRole("button", { name: "Issue registration token" }).click();
    const token = page.getByRole("dialog", { name: "Registration access token" });
    await expect(token.getByTestId("secret-value").nth(1)).toContainText(`/register/e2e-web-${suffix}`, { timeout: 10_000 });
    await token.getByRole("button", { name: "I have stored it" }).click();
  });

  test("playground runs a real sign-in for a public client", async ({ page }) => {
    await consoleLogin(page, loadState());
    await openClients(page);
    await page.getByRole("button", { name: "New client" }).click();
    const dialog = page.getByRole("dialog", { name: "New client" });
    await dialog.getByLabel("Name").fill(spaName);
    await dialog.getByRole("button", { name: "Next" }).click();
    await dialog.getByRole("switch", { name: "Ask users for consent" }).click();
    await dialog.getByRole("button", { name: "Next" }).click();
    await dialog.getByLabel("Redirect URIs", { exact: true }).fill("https://spa.example.com/cb");
    await page.keyboard.press("Enter");
    await dialog.getByRole("button", { name: "Next" }).click();
    await dialog.getByRole("button", { name: "Create client" }).click();
    await expect(page.getByRole("heading", { name: spaName, level: 1 })).toBeVisible({ timeout: 15_000 });

    await page.getByRole("link", { name: "Playground" }).click();
    await expect(page.getByRole("heading", { name: "Playground", level: 1 })).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in as a user" })).toBeDisabled();
    await page.getByRole("button", { name: "Add it to the redirect URIs" }).click();
    await expect(page.getByRole("button", { name: "Sign in as a user" })).toBeEnabled({ timeout: 10_000 });
    await expectAccessible(page);

    // The sign-in runs in a popup; the browser already holds the tenant
    // session, so it comes straight back with a code, hands it over and closes.
    const [popup] = await Promise.all([page.waitForEvent("popup"), page.getByRole("button", { name: "Sign in as a user" }).click()]);
    await popup.waitForEvent("close", { timeout: 20_000 });
    await expect(page.getByRole("heading", { name: "Token response" })).toBeVisible({ timeout: 15_000 });
    // Nothing of the run (the tokens, a client secret) is left in storage.
    expect(await page.evaluate(() => Object.keys(sessionStorage).filter((k) => k.startsWith("ridm.playground")))).toEqual([]);
    await expect(page.getByRole("heading", { name: "ID token claims" })).toBeVisible();
    await expect(page.getByText('"iss"').first()).toBeVisible();
    await page.getByRole("button", { name: "Call userinfo" }).click();
    await expect(page.getByRole("heading", { name: "userinfo" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(loadState().email).first()).toBeVisible();
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(page.getByRole("heading", { name: "userinfo" })).toBeHidden({ timeout: 10_000 });
    await expect(page.getByRole("heading", { name: "Token response" })).toBeVisible();
    await expectAccessible(page);
  });

  test("deletes both clients", async ({ page }) => {
    await consoleLogin(page, loadState());
    for (const name of [webName, spaName]) {
      await openDetail(page, name);
      await page.getByRole("button", { name: "Delete client" }).click();
      await page.getByRole("dialog", { name: `Delete ${name}?` }).getByRole("button", { name: "Delete client" }).click();
      await page.waitForURL(/\/console\/clients\/\?tenant=master$/, { timeout: 15_000 });
      await page.getByLabel("Search clients").fill(name);
      await expect(page.getByText("No client matches.")).toBeVisible({ timeout: 10_000 });
    }
  });
});
