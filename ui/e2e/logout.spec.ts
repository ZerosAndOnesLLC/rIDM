import { expect, test } from "@playwright/test";
import { authorizeUrl, expectAccessible, finishAuthorization, loadState, loginWithPassword, t } from "./helpers";

test("RP-initiated logout asks for confirmation, ends the session, returns to the app", async ({ page }) => {
  const s = loadState();
  await loginWithPassword(page, s);
  await finishAuthorization(page);

  const q = new URLSearchParams({ client_id: s.client_id, post_logout_redirect_uri: `${s.ui}/callback/`, state: "bye" });
  await page.goto(`${t("/end_session")}?${q}`);
  await expect(page).toHaveURL(/\/logout\//);
  await expect(page.getByRole("heading", { name: /Sign out of E2E App/ })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL(/\/callback\//);
  expect(new URL(page.url()).searchParams.get("state")).toBe("bye");

  // The session is gone: the next authorization asks to sign in again.
  await page.goto(authorizeUrl(s));
  await expect(page).toHaveURL(/\/login\//);
});
