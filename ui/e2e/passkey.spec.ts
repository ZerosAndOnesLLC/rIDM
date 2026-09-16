import { expect, test, type BrowserContext, type CDPSession, type Page } from "@playwright/test";
import { authorizeUrl, expectAccessible, finishAuthorization, loadState, loginWithPassword, tenantId, tenantSql } from "./helpers";

/**
 * Passkeys through a CDP virtual authenticator (resident key, user
 * verification): enrolment as the second step of a client step-up, then a
 * passwordless sign-in with the same key, then a step-up verified by it.
 * One page is shared so the authenticator keeps its credential across tests.
 */

const STEP_UP = { acr_values: "urn:ridm:acr:mfa" };

test.describe("passkeys", () => {
  test.describe.configure({ mode: "serial" });
  let context: BrowserContext;
  let page: Page;
  let cdp: CDPSession;

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext();
    page = await context.newPage();
    cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
  });

  test.afterAll(async () => {
    await context.close();
    // Leave the shared e2e user as the other specs expect it.
    const tid = tenantId();
    tenantSql(`DELETE FROM credentials WHERE tenant_id = '${tid}' AND user_id = (SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${loadState().email}') AND type IN ('webauthn','recovery_code')`);
  });

  test("a step-up enrols a passkey as the second step and shows recovery codes", async () => {
    const s = loadState();
    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: "Set up two-step verification" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: /^Passkey/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Authenticator app/ })).toBeVisible();
    await expectAccessible(page);

    await page.getByRole("button", { name: /^Passkey/ }).click();
    await expect(page.getByRole("heading", { name: "Add a passkey" })).toBeVisible();
    await expectAccessible(page);
    // The other choice is a step back.
    await page.getByRole("button", { name: "Choose another method" }).click();
    await expect(page.getByRole("heading", { name: "Set up two-step verification" })).toBeVisible();
    await page.getByRole("button", { name: /^Passkey/ }).click();

    await page.getByLabel("Name this passkey (optional)").fill("Laptop");
    await page.getByRole("button", { name: "Create a passkey" }).click();
    await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible({ timeout: 15_000 });
    const codes = (await page.getByRole("list", { name: "Save your recovery codes" }).getByRole("listitem").allTextContents()).map((c) => c.trim());
    expect(codes).toHaveLength(10);
    await page.getByRole("button", { name: "I have saved my codes" }).click();
    await finishAuthorization(page);

    const tid = tenantId();
    const label = tenantSql(`SELECT label FROM credentials WHERE tenant_id = '${tid}' AND type = 'webauthn' AND user_id = (SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${s.email}')`);
    expect(label).toBe("Laptop");
  });

  test("the passkey signs in without a password", async () => {
    const s = loadState();
    await page.goto(authorizeUrl(s, { prompt: "login" }));
    await page.waitForURL(/\/login\//);
    await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
    await expectAccessible(page);
    await page.getByRole("button", { name: "Sign in with a passkey" }).click();
    // A verified passkey is two factors already: no second step follows.
    await finishAuthorization(page);
    expect(page.url()).not.toMatch(/\/mfa\//);
  });

  test("a step-up after a password sign-in verifies with the passkey", async () => {
    const s = loadState();
    await loginWithPassword(page, s, STEP_UP);
    await page.waitForURL(/\/mfa\//, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: "Two-step verification" })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("Use your passkey to continue.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Use a recovery code" })).toBeVisible();
    await expectAccessible(page);
    await page.getByRole("button", { name: "Continue with passkey" }).click();
    await finishAuthorization(page);
  });
});
