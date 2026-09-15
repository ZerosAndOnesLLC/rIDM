import { expect, test } from "@playwright/test";
import { alertOf, consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/**
 * The admin console shell: PKCE sign-in through the tenant's login page,
 * the frame (sidebar, tenant switcher, search, theme, shortcuts) and
 * sign-out that ends the browser session.
 */
test.describe("admin console shell", () => {
  test("sign-in card is accessible and validates the tenant", async ({ page }) => {
    await page.goto("/console/");
    await expect(page.getByRole("heading", { name: "Sign in to the console" })).toBeVisible();
    await expectAccessible(page);
    await page.getByLabel("Tenant").fill("Not A Slug!");
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(alertOf(page)).toContainText("tenant slug");
    expect(page.url()).toContain("/console/");
  });

  test("signs in with PKCE, shows the shell, and returns to the deep link", async ({ page }) => {
    const state = loadState();
    await page.goto(`/console/?tenant=${TENANT}&from=deep`);
    await page.getByLabel("Tenant").fill(TENANT);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.waitForURL(/\/login\//);
    await page.getByLabel("Email or username").fill(state.email);
    await page.getByLabel("Password", { exact: true }).fill(state.password);
    await page.getByRole("button", { name: "Continue" }).click();
    // No consent step for the built-in client; back where we started.
    await page.waitForURL(/\/console\/\?tenant=master&from=deep$/, { timeout: 20_000 });

    await expect(page.getByTestId("me-username")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Console" }).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("button", { name: /Tenant: master/ })).toBeVisible();
    await expect(page.getByText("Global administrator")).toBeVisible();
    await expect(page.getByText("ridm:owner")).toBeVisible();
    // The dashboard: tiles, the sign-ins chart with its table view, top clients.
    await expect(page.getByText("Live sessions")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("img", { name: /Sign-ins and failed sign-ins per day/ })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Most authorized clients" })).toBeVisible();
    await page.getByText("Table view").click();
    await expect(page.getByRole("columnheader", { name: "Failed" })).toBeVisible();
    await page.getByLabel("Window").selectOption("7");
    await expect(page.getByText("Sign-ins · 7 days", { exact: true })).toBeVisible({ timeout: 10_000 });
    await expectAccessible(page);

    // The session survives a reload in the same tab (no second login round trip).
    await page.reload();
    await expect(page.getByTestId("me-username")).toBeVisible({ timeout: 15_000 });
    expect(page.url()).not.toContain("/login/");
  });

  test("global search finds pages, users and clients", async ({ page }) => {
    const state = loadState();
    await consoleLogin(page, state);
    await page.keyboard.press("Control+k");
    const box = page.getByRole("combobox", { name: "Search" });
    await expect(box).toBeFocused();
    await expect(page.getByRole("option", { name: /Overview/ })).toBeVisible();
    await expectAccessible(page);

    await box.fill(state.email.slice(0, 12));
    await expect(page.getByRole("option", { name: new RegExp(state.email) })).toBeVisible({ timeout: 10_000 });
    await box.fill("E2E App");
    await expect(page.getByRole("option", { name: /E2E App/ }).first()).toBeVisible({ timeout: 10_000 });
    await box.fill("zzz-nothing-here");
    await expect(page.getByText("Nothing matches.")).toBeVisible({ timeout: 10_000 });
    await page.keyboard.press("Escape");
    await expect(box).toBeHidden();
  });

  test("tenant switcher lists tenants and shortcuts help opens", async ({ page }) => {
    const state = loadState();
    await consoleLogin(page, state);
    await page.getByRole("button", { name: /Switch tenant/ }).click();
    const box = page.getByRole("combobox", { name: "Switch tenant" });
    await expect(page.getByRole("option", { name: /master/ })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("option", { name: /master/ })).toContainText("current");
    await expectAccessible(page);
    await box.fill("mast");
    await page.keyboard.press("Enter");
    await page.waitForURL(/\/console\/\?tenant=master$/);

    await page.keyboard.press("t");
    await expect(page.getByRole("combobox", { name: "Switch tenant" })).toBeVisible();
    await page.keyboard.press("Escape");

    await page.keyboard.press("?");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    await expect(page.getByText("Switch tenant", { exact: true })).toBeVisible();
    await expectAccessible(page);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();

    // `g o` goes to the overview.
    await page.keyboard.press("g");
    await page.keyboard.press("o");
    await page.waitForURL(/\/console\/\?tenant=master$/);
  });

  test("theme choice applies at once and survives a reload", async ({ page }) => {
    const state = loadState();
    await consoleLogin(page, state);
    const html = page.locator("html");
    await expect(html).not.toHaveAttribute("data-theme", /.+/);
    await page.getByRole("button", { name: "Dark theme" }).click();
    await expect(html).toHaveAttribute("data-theme", "dark");
    await expect(page.getByRole("button", { name: "Dark theme" })).toHaveAttribute("aria-pressed", "true");
    await expectAccessible(page);
    await page.reload();
    await expect(html).toHaveAttribute("data-theme", "dark");
    await page.getByRole("button", { name: "Follow system theme" }).click({ timeout: 15_000 });
    await expect(html).not.toHaveAttribute("data-theme", /.+/);
  });

  test("sign-out ends the browser session", async ({ page }) => {
    const state = loadState();
    await consoleLogin(page, state);
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.waitForURL(/\/console\/$/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "Sign in to the console" })).toBeVisible();
    // The tenant's SSO session is gone too: signing in again asks for credentials.
    await page.getByLabel("Tenant").fill(TENANT);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.waitForURL(/\/login\//);
    await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
  });

  test("a callback that belongs to no sign-in is refused", async ({ page }) => {
    await page.goto("/console/callback/?code=abc&state=nope");
    await expect(alertOf(page)).toContainText("does not belong");
    await page.getByRole("link", { name: "Back to sign-in" }).click();
    await expect(page.getByRole("heading", { name: "Sign in to the console" })).toBeVisible();
  });
});

/** Mobile: the navigation lives in a drawer. */
test.describe("admin console on a phone", () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test("navigation drawer opens and closes", async ({ page }) => {
    const state = loadState();
    await consoleLogin(page, state);
    await expect(page.getByRole("navigation", { name: "Console" })).toBeHidden();
    await page.getByRole("button", { name: "Open navigation" }).click();
    await expect(page.getByRole("dialog", { name: "Navigation" }).getByRole("link", { name: "Overview" })).toBeVisible();
    await expectAccessible(page);
    await page.getByRole("button", { name: "Close navigation" }).click();
    await expect(page.getByRole("dialog", { name: "Navigation" })).toBeHidden();
  });
});

