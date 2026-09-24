import { expect, test } from "@playwright/test";
import { authorizeUrl, expectAccessible, finishAuthorization, loadState, mailpit } from "./helpers";

test("magic link: request by email, open the link, reach the callback", async ({ page }) => {
  const s = loadState();
  await page.goto(authorizeUrl(s, { prompt: "login" }));
  await page.getByRole("button", { name: "Email me a sign-in link" }).click();
  await page.getByLabel("Email").fill(s.email);
  await page.getByRole("button", { name: "Send link" }).click();
  await expect(page.getByText("Check your email")).toBeVisible();
  await expectAccessible(page);

  const mail = await mailpit.waitFor(s.email, 15_000, "Sign in to");
  const link = mail.links.find((l) => l.includes("magic="));
  expect(link, mail.text).toBeTruthy();
  await page.goto(link!);
  await finishAuthorization(page);
});
