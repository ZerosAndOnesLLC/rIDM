import { expect, test } from "@playwright/test";
import {
  clearTenantCache,
  expectAccessible,
  finishAuthorization,
  loadState,
  loginWithPassword,
  tenantId,
  tenantSql,
} from "./helpers";

test("a newly required profile attribute is collected at the next login", async ({ page }) => {
  const s = loadState();
  const tid = tenantId();
  const schema = JSON.stringify([
    { name: "department", type: "string", label: "Department", required: true, editable_by: "user", visible_in: ["userinfo"] },
  ]);
  tenantSql(
    `INSERT INTO user_profile_schema (tenant_id, attributes) VALUES ('${tid}', '${schema}'::jsonb) ` +
      `ON CONFLICT (tenant_id) DO UPDATE SET attributes = EXCLUDED.attributes`,
  );
  clearTenantCache();
  try {
    await loginWithPassword(page, s);
    await expect(page.getByRole("heading", { name: "Complete your profile" })).toBeVisible();
    await expectAccessible(page);
    await page.getByLabel("Department").fill("Engineering");
    await page.getByRole("button", { name: "Continue" }).click();
    await finishAuthorization(page);
    expect(tenantSql(`SELECT attributes->>'department' FROM users WHERE email = '${s.email}'`)).toBe("Engineering");
  } finally {
    tenantSql(`UPDATE user_profile_schema SET attributes = '[]'::jsonb WHERE tenant_id = '${tid}'`);
    clearTenantCache();
  }
});

test("terms must be accepted at login when the user has not accepted them", async ({ page }) => {
  const s = loadState();
  tenantSql(`UPDATE users SET terms_accepted_at = NULL WHERE email = '${s.email}'`);

  await loginWithPassword(page, s);
  await expect(page.getByRole("heading", { name: "Terms of service" })).toBeVisible();
  await expect(page.getByRole("link", { name: "terms of service" })).toHaveAttribute("href", "https://example.com/terms");
  await expect(page.getByRole("button", { name: "I accept" })).toBeDisabled();
  await expectAccessible(page);

  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "I accept" }).click();
  await finishAuthorization(page);
  expect(tenantSql(`SELECT terms_accepted_at IS NOT NULL FROM users WHERE email = '${s.email}'`)).toBe("t");
});
