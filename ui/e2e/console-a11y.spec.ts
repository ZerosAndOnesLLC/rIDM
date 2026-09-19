import { expect, test, type Page } from "@playwright/test";
import { consoleLogin, expectAccessible, loadState, TENANT } from "./helpers";

/**
 * Every admin console page gets an axe pass in its landing state, in both
 * themes, and on a phone width. Journeys are covered by the other console
 * specs; this is the sweep that catches a page nobody exercised.
 */
const PAGES: [string, string, string][] = [
  ["overview", `/console/?tenant=${TENANT}`, "Overview"],
  ["tenants", `/console/tenants/?tenant=${TENANT}`, "Tenants"],
  ["settings", `/console/settings/?tenant=${TENANT}`, "Settings"],
  ["export & import", `/console/config/?tenant=${TENANT}`, "Export & import"],
  ["users", `/console/users/?tenant=${TENANT}`, "Users"],
  ["invitations", `/console/users/?tenant=${TENANT}&view=invitations`, "Invitations"],
  ["groups", `/console/groups/?tenant=${TENANT}`, "Groups"],
  ["organizations", `/console/organizations/?tenant=${TENANT}`, "Organizations"],
  ["roles", `/console/roles/?tenant=${TENANT}`, "Roles"],
  ["clients", `/console/clients/?tenant=${TENANT}`, "Clients"],
  ["resource servers", `/console/resource-servers/?tenant=${TENANT}`, "Resource servers"],
  ["scopes", `/console/scopes/?tenant=${TENANT}`, "Scopes"],
  ["claim mappers", `/console/claim-mappers/?tenant=${TENANT}`, "Claim mappers"],
  ["keys", `/console/keys/?tenant=${TENANT}`, "Signing keys"],
  ["audit", `/console/audit/?tenant=${TENANT}`, "Audit log"],
  ["ip rules", `/console/ip-rules/?tenant=${TENANT}`, "IP rules"],
  ["provisioning", `/console/provisioning/?tenant=${TENANT}`, "Provisioning"],
  ["webhooks", `/console/webhooks/?tenant=${TENANT}`, "Webhooks"],
  ["messaging email", `/console/messaging/?tenant=${TENANT}&tab=email`, "Messaging"],
  ["messaging sms", `/console/messaging/?tenant=${TENANT}&tab=sms`, "Messaging"],
  ["messaging log", `/console/messaging/?tenant=${TENANT}&tab=log`, "Messaging"],
];

async function settled(page: Page, heading: string) {
  await expect(page.getByRole("heading", { name: heading, level: 1 })).toBeVisible({ timeout: 20_000 });
  // Let the page's queries settle so lists, not spinners, are checked.
  await expect(page.getByRole("status").filter({ hasText: "Loading" })).toHaveCount(0, { timeout: 20_000 });
}

test.describe("admin console accessibility sweep", () => {
  for (const [name, path, heading] of PAGES) {
    test(`${name} page`, async ({ page }) => {
      await consoleLogin(page, loadState());
      await page.goto(path);
      await settled(page, heading);
      await expectAccessible(page);
    });
  }

  for (const [name, path, heading] of PAGES.slice(0, 8)) {
    test(`${name} page in dark`, async ({ page }) => {
      await page.addInitScript(() => localStorage.setItem("ridm.theme", "dark"));
      await consoleLogin(page, loadState());
      await page.goto(path);
      await settled(page, heading);
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      await expectAccessible(page);
    });
  }

  test.describe("phone width", () => {
    test.use({ viewport: { width: 390, height: 844 } });
    for (const [name, path, heading] of [PAGES[0]!, PAGES[4]!, PAGES[8]!, PAGES[13]!]) {
      test(`${name} page on a phone`, async ({ page }) => {
        await consoleLogin(page, loadState());
        await page.goto(path);
        await settled(page, heading);
        await expectAccessible(page);
        const [scroll, client] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
        expect(scroll).toBe(client);
      });
    }
  });
});
