import { expect, test } from "@playwright/test";
import { authorizeUrl, expectAccessible, finishAuthorization, loadState, mailpit } from "./helpers";

test("registration with email verification signs the new user in", async ({ page }) => {
  const s = loadState();
  const email = `reg-${Date.now()}@example.com`;
  await page.goto(authorizeUrl(s, { prompt: "create" }));
  await expect(page).toHaveURL(/\/register\//);
  await expect(page.getByRole("heading", { name: "Create your account" })).toBeVisible();
  await expectAccessible(page);

  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill("correct-horse-battery-staple");
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Create your account" }).click();
  await expect(page.getByRole("status")).toContainText(email);
  await expectAccessible(page);

  const mail = await mailpit.waitFor(email);
  const link = mail.links.find((l) => l.includes("/verify/"));
  expect(link, mail.text).toBeTruthy();
  await page.goto(link!);
  await finishAuthorization(page);
});
