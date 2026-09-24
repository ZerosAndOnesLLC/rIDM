import { expect, test } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/** A CA certificate (EC P-256, `CN=E2E Test CA`, valid until 2126) for the trust-anchor journey. */
const CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBlDCCATmgAwIBAgIUSef3IZd2YboCamGacaL8E0NVuZMwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLRTJFIFRlc3QgQ0EwIBcNMjYwOTIyMTg1MTE3WhgPMjEyNjA4
MjkxODUxMTdaMBYxFDASBgNVBAMMC0UyRSBUZXN0IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEuoJ3pEzzVxtBXx56vDb+GCoGXTe376S+eBmxJ/ApOHmy4YE6
zbMf2mP4WkfGorWtqvawvH+gfpB/IIfRf3FlcKNjMGEwHQYDVR0OBBYEFOwpJ8GU
v8QNGL2dE9z1nJ1QDtDpMB8GA1UdIwQYMBaAFOwpJ8GUv8QNGL2dE9z1nJ1QDtDp
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kA
MEYCIQCtSfleSX4Sg1THOxbkmILb3IbEmnDZVHnpp4rXwL0qwQIhAPXMH0FNOInS
8QGePwgKNWJH3JkGfDy/DrBfh4wizPLb
-----END CERTIFICATE-----`;

/**
 * Mutual TLS (RFC 8705): the tenant's client-certificate authorities, and a
 * client switched to `tls_client_auth` with its subject, saved as you go.
 */
test.describe("mutual TLS", () => {
  const suffix = loadState().email.replace(/\D/g, "").slice(-9);

  test("client certificates: add a certificate authority, refuse a bad one, remove it", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/client-certificates/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Client certificates", level: 1 })).toBeVisible({ timeout: 15_000 });

    await page.getByLabel("Name", { exact: true }).fill(`E2E CA ${suffix}`);
    await page.getByLabel("CA certificate (PEM)").fill("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----");
    await page.getByRole("button", { name: "Add certificate authority" }).click();
    await expect(page.getByRole("alert").filter({ hasText: /X\.509/ })).toBeVisible({ timeout: 10_000 });

    await page.getByLabel("CA certificate (PEM)").fill(CA_PEM);
    await page.getByRole("button", { name: "Add certificate authority" }).click();
    const row = page.getByRole("row").filter({ hasText: `E2E CA ${suffix}` });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await expect(row).toContainText("CN=E2E Test CA");
    await expectAccessible(page);

    await page.getByRole("button", { name: `Remove E2E CA ${suffix}` }).click();
    const dialog = page.getByRole("dialog", { name: `Remove E2E CA ${suffix}?` });
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Remove" }).click();
    await expect(row).toBeHidden({ timeout: 10_000 });
  });

  test("a client switches to mutual TLS once its certificate subject is entered", async ({ page }) => {
    await consoleLogin(page, loadState());
    const name = `E2E mTLS ${suffix}`;
    await page.goto(`/console/clients/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Clients", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New client" }).click();
    const wizard = page.getByRole("dialog", { name: "New client" });
    await wizard.getByRole("radio", { name: /Machine to machine/ }).check();
    await wizard.getByLabel("Name").fill(name);
    await wizard.getByLabel("Client ID").fill(`e2e-mtls-${suffix}`);
    await wizard.getByRole("button", { name: "Next" }).click();
    // Mutual TLS is chosen on the detail page, where its subject is entered.
    await expect(wizard.getByRole("option", { name: /Mutual TLS/ })).toHaveCount(0);
    // URIs (none for a machine client), then scopes.
    await wizard.getByRole("button", { name: "Next" }).click();
    await wizard.getByRole("button", { name: "Next" }).click();
    await wizard.getByRole("button", { name: "Create client" }).click();
    const reveal = page.getByRole("dialog", { name: `${name} created` });
    await expect(reveal).toBeVisible({ timeout: 15_000 });
    await reveal.getByRole("button", { name: "I have stored it" }).click();
    await expect(page.getByRole("heading", { name, level: 1 })).toBeVisible({ timeout: 15_000 });
    const method = page.getByRole("combobox", { name: "Client authentication" });
    await method.selectOption("tls_client_auth");
    // Nothing is saved until the subject is there.
    await expect(page.getByText("Enter the subject to switch to mutual TLS.")).toBeVisible();
    await page.getByRole("combobox", { name: "Certificate subject" }).selectOption("tls_client_auth_san_dns");
    await page.getByLabel("DNS name (SAN)").fill("billing.acme.example");
    await page.getByRole("switch", { name: "Certificate-bound access tokens" }).click();
    await expect(page.getByRole("status").filter({ hasText: /^Saved$/ })).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);

    await page.reload();
    await expect(page.getByRole("combobox", { name: "Client authentication" })).toHaveValue("tls_client_auth", { timeout: 15_000 });
    await expect(page.getByLabel("DNS name (SAN)")).toHaveValue("billing.acme.example");
    await expect(page.getByRole("switch", { name: "Certificate-bound access tokens" })).toHaveAttribute("aria-checked", "true");

    // Back to a secret: the subject goes with it.
    await page.getByRole("combobox", { name: "Client authentication" }).selectOption("client_secret_basic");
    await expect(page.getByLabel("DNS name (SAN)")).toBeHidden();
  });
});
