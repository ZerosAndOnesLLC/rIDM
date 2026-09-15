import { expect, test } from "@playwright/test";
import { alertOf, expectAccessible, TENANT } from "./helpers";

// Pages not exercised by a flow above still get an accessibility pass.
for (const [name, path, heading] of [
  ["error", `/error/?tenant=${TENANT}&error=invalid_request&error_description=The%20redirect%20URI%20is%20not%20registered`, "Something went wrong"],
  ["device", `/device/?tenant=${TENANT}`, "Connect a device"],
  ["invite (invalid token)", `/invite/?tenant=${TENANT}&token=nope`, "You're invited"],
  ["verify (no token)", `/verify/?tenant=${TENANT}`, "Verify your email"],
  ["logout (signed out)", `/logout/?tenant=${TENANT}&done=1`, "Signing out"],
  ["login (missing tenant)", "/login/", null],
] as const) {
  test(`${name} page is accessible`, async ({ page }) => {
    await page.goto(path);
    if (heading) await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    else await expect(alertOf(page)).toContainText("missing the service");
    await expectAccessible(page);
  });
}
