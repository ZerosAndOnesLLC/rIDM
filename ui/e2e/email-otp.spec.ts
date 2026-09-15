import { expect, test } from "@playwright/test";
import { alertOf, authorizeUrl, expectAccessible, finishAuthorization, loadState, mailpit } from "./helpers";

test("email code: a wrong code is refused, the emailed one signs in", async ({ page }) => {
  const s = loadState();
  await page.goto(authorizeUrl(s, { prompt: "login" }));
  await expect(page).toHaveURL(/\/login\//);
  await page.getByRole("button", { name: "Email me a code" }).click();
  await expect(page.getByLabel("Email")).toBeVisible();
  await expectAccessible(page);

  await page.getByLabel("Email").fill(s.email);
  await page.getByRole("button", { name: "Send code" }).click();
  await expect(page.getByRole("heading", { name: "Enter the code" })).toBeVisible();
  await expect(page.getByText(s.email)).toBeVisible();
  await expectAccessible(page);

  const mail = await mailpit.waitFor(s.email);
  const code = /\b(\d{6})\b/.exec(mail.text)?.[1];
  expect(code, mail.text).toBeTruthy();

  await page.getByLabel("Code").fill(code === "000000" ? "111111" : "000000");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(alertOf(page)).toContainText("invalid");
  await expectAccessible(page);

  await page.getByLabel("Code").fill(code!);
  await page.getByRole("button", { name: "Continue" }).click();
  await finishAuthorization(page);
});
