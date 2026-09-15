import { expect, test } from "@playwright/test";
import { alertOf, authorizeUrl, expectAccessible, finishAuthorization, loadState, loginWithPassword } from "./helpers";

test("password login: wrong password is refused, right one reaches the callback", async ({ page }) => {
  const s = loadState();
  await page.goto(authorizeUrl(s));
  await expect(page).toHaveURL(/\/login\//);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByText("to continue to E2E App")).toBeVisible();
  await expectAccessible(page);

  await page.getByLabel("Email or username").fill(s.email);
  await page.getByLabel("Password", { exact: true }).fill("not-the-password");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(alertOf(page)).toContainText("Incorrect");
  await expectAccessible(page);

  await page.getByLabel("Password", { exact: true }).fill(s.password);
  await page.getByRole("button", { name: "Continue" }).click();
  await finishAuthorization(page);
});

test("an existing session skips the login page; prompt=login asks again", async ({ page }) => {
  const s = loadState();
  await loginWithPassword(page, s);
  await finishAuthorization(page);
  await page.goto(authorizeUrl(s));
  await page.waitForURL(/\/callback\//);
  expect(new URL(page.url()).searchParams.get("code")).toBeTruthy();
  await page.goto(authorizeUrl(s, { prompt: "login" }));
  await expect(page).toHaveURL(/\/login\//);
});
