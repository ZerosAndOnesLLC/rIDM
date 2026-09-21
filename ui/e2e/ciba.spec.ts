import { expect, test, type Page } from "@playwright/test";
import { API, expectAccessible, loadState, mailpit, t, TENANT } from "./helpers";

/**
 * Backchannel sign-in (Phase 12.6, CIBA): an application names the user at
 * `/bc-authorize`, the user is emailed a link to the account console's
 * Requests page, compares the binding message and approves, and the
 * application then collects the tokens with the CIBA grant. The client is
 * registered dynamically, as the e2e tenant allows.
 */
const state = loadState();
const CIBA = "urn:openid:params:grant-type:ciba";

async function registerCibaClient(): Promise<{ id: string; secret: string }> {
  const res = await fetch(`${API}${t("/register")}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "E2E Bank",
      grant_types: [CIBA],
      token_endpoint_auth_method: "client_secret_basic",
      backchannel_token_delivery_mode: "poll",
      scope: "openid profile",
    }),
  });
  if (!res.ok) throw new Error(`CIBA client registration failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { client_id: string; client_secret: string };
  return { id: body.client_id, secret: body.client_secret };
}

async function asClient(client: { id: string; secret: string }, path: string, form: Record<string, string>) {
  const res = await fetch(`${API}${t(path)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${Buffer.from(`${client.id}:${client.secret}`).toString("base64")}`,
    },
    body: new URLSearchParams(form),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** Follow the emailed link in a fresh browser: the account console sends it to sign in first. */
async function accountSignIn(page: Page, url: string) {
  await page.goto(url);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL(/\/login\//);
  await page.getByLabel("Email or username").fill(state.email);
  await page.getByLabel("Password", { exact: true }).fill(state.password);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL(/\/account\/approvals\//, { timeout: 20_000 });
  await expect(page.getByRole("heading", { name: "Sign-in requests", level: 1 })).toBeVisible({ timeout: 20_000 });
}

test("an application signs the user in over the back channel", async ({ page }) => {
  // Its own binding message, so a retry never mistakes an earlier attempt's request for its own.
  const binding = `E2E ${Math.floor(1000 + Math.random() * 9000)}`;
  const client = await registerCibaClient();
  const ack = await asClient(client, "/bc-authorize", {
    scope: "openid profile",
    login_hint: state.email,
    binding_message: binding,
  });
  expect(ack.status).toBe(200);
  const authReqId = ack.body.auth_req_id as string;

  const pending = await asClient(client, "/token", { grant_type: CIBA, auth_req_id: authReqId });
  expect(pending.body.error).toBe("authorization_pending");

  // The notice links to the approvals page for this request.
  const mail = await mailpit.waitFor(state.email, 15_000, "E2E Bank");
  expect(mail.text).toContain(binding);
  const link = mail.links.find((l) => l.includes("/account/approvals/"));
  expect(link, mail.text).toBeTruthy();
  expect(link).toContain(`tenant=${TENANT}`);

  await accountSignIn(page, link!);
  const item = page.getByRole("list", { name: "Waiting for your answer" }).getByRole("listitem").filter({ hasText: binding });
  await expect(item.getByText("E2E Bank asks to sign you in")).toBeVisible();
  await expectAccessible(page);
  await item.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("E2E Bank is signed in.")).toBeVisible();
  await expect(item).toHaveCount(0);

  const tokens = await asClient(client, "/token", { grant_type: CIBA, auth_req_id: authReqId });
  expect(tokens.status).toBe(200);
  expect(typeof tokens.body.id_token).toBe("string");
  expect(typeof tokens.body.access_token).toBe("string");

  // The approval is remembered: the bank is a connected application now.
  await page.getByRole("link", { name: "Applications" }).click();
  await expect(page.getByText("E2E Bank").first()).toBeVisible({ timeout: 15_000 });
});
