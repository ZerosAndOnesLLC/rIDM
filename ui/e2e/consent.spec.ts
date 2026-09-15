import { expect, test } from "@playwright/test";
import { expectAccessible, loadState, loginWithPassword } from "./helpers";

test("consent can be denied and returns access_denied to the app", async ({ page }) => {
  const s = loadState();
  await loginWithPassword(page, s, { prompt: "login consent" });
  await page.waitForURL(/\/consent\//);
  await expect(page.getByRole("heading", { name: "Allow access?" })).toBeVisible();
  await expect(page.getByText("Sign you in")).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: "Deny" }).click();
  await page.waitForURL(/\/callback\//);
  const url = new URL(page.url());
  expect(url.searchParams.get("error")).toBe("access_denied");
  expect(url.searchParams.get("state")).toBe("st");
});
