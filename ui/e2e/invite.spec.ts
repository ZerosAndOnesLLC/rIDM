import { createHash, randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { TENANT, expectAccessible, finishAuthorization, loadState, loginWithPassword, tenantId, tenantSql } from "./helpers";

test("an invited person sets a password once, then signs in with it", async ({ page }) => {
  const s = loadState();
  const email = `invited-${Date.now()}@example.com`;
  const password = "invited-people-choose-passphrases";
  // Invitations are created by administrators (admin API, Phase 5.7); until
  // then the row is written the way the service writes it: SHA-256 of the token.
  const token = randomBytes(32).toString("base64url");
  const hash = createHash("sha256").update(token).digest("hex");
  tenantSql(
    `INSERT INTO invitations (tenant_id, email, token_hash, expires_at) ` +
      `VALUES ('${tenantId()}', '${email}', decode('${hash}', 'hex'), now() + interval '1 day')`,
  );

  await page.goto(`/invite/?tenant=${TENANT}&token=${token}`);
  await expect(page.getByRole("heading", { name: "You're invited" })).toBeVisible();
  await expect(page.getByText(`for ${email}`)).toBeVisible();
  await expect(page.getByLabel("Email")).toHaveValue(email);
  await expectAccessible(page);

  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByText("Your account is ready.")).toBeVisible();
  await expectAccessible(page);

  // Single use.
  await page.goto(`/invite/?tenant=${TENANT}&token=${token}`);
  await expect(page.getByText("This invitation is invalid, expired, or already used.")).toBeVisible();

  await loginWithPassword(page, { ...s, email, password });
  await finishAuthorization(page);
});
