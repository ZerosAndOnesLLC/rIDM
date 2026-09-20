import { expect, test, type Page } from "@playwright/test";
import {
  clearRolesVersion,
  consoleLogin,
  expectAccessible,
  finishAuthorization,
  loadState,
  loginWithPassword,
  registerVerifiedUser,
  TENANT,
  tenantId,
  tenantSql,
} from "./helpers";

/**
 * Organizations (Phase 12.1): a user in two of them chooses one while signing
 * in, and the account console lists what they belong to. The rows are written
 * straight to the database, as the console's own coverage lives elsewhere; the
 * roles version is dropped so the API re-reads the memberships.
 */
const state = loadState();
const tid = tenantId();

function userId(): string {
  return tenantSql(`SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${state.email}'`);
}

function makeOrg(slug: string, name: string): string {
  tenantSql(
    `INSERT INTO organizations (tenant_id, slug, display_name) VALUES ('${tid}', '${slug}', '${name}')
     ON CONFLICT (tenant_id, slug) DO NOTHING`,
  );
  // A separate read: psql prints the command tag after a RETURNING row.
  return tenantSql(
    `SELECT id FROM organizations WHERE tenant_id = '${tid}' AND slug = '${slug}'`,
  );
}

function join(org: string, user: string) {
  tenantSql(
    `INSERT INTO organization_members (tenant_id, org_id, user_id) VALUES ('${tid}', '${org}', '${user}')
     ON CONFLICT DO NOTHING`,
  );
  // Memberships are cached under the tenant's roles version.
  clearRolesVersion(tid);
}

function cleanUp() {
  tenantSql(`DELETE FROM role_assignments WHERE tenant_id = '${tid}' AND org_id IS NOT NULL`);
  tenantSql(`DELETE FROM organizations WHERE tenant_id = '${tid}'`);
  tenantSql(`UPDATE users SET org_id = NULL WHERE tenant_id = '${tid}' AND org_id IS NOT NULL`);
  clearRolesVersion(tid);
}

/**
 * Sign into the account console and land on `path`. The browser already holds
 * an SSO session here, so the tenant's login page may not ask again.
 */
async function accountSignIn(page: Page, path: string, heading: string) {
  await page.goto(`${path}?tenant=${TENANT}`);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  const password = page.getByLabel("Password", { exact: true });
  if (await password.isVisible({ timeout: 10_000 }).catch(() => false)) {
    await page.getByLabel("Email or username").fill(state.email);
    await password.fill(state.password);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
  }
  await expect(page.getByRole("heading", { name: heading, level: 1 })).toBeVisible({
    timeout: 20_000,
  });
}

test.afterAll(cleanUp);

test("a member of two organizations picks one while signing in", async ({ page }) => {
  cleanUp();
  const uid = userId();
  const acme = makeOrg("acme-e2e", "Acme (e2e)");
  const globex = makeOrg("globex-e2e", "Globex (e2e)");
  join(acme, uid);
  join(globex, uid);

  await loginWithPassword(page, state);
  await expect(page.getByRole("heading", { name: "Choose an organization" })).toBeVisible();
  await expect(page.getByRole("radio", { name: /Acme \(e2e\)/ })).toBeVisible();
  await expectAccessible(page);

  // The choice carries through to the authorization, which then completes.
  await page.getByRole("radio", { name: /Globex \(e2e\)/ }).check();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await finishAuthorization(page);

  // The session acts in the organization that was chosen.
  const sessions = tenantSql(
    `SELECT count(*) FROM sso_sessions WHERE tenant_id = '${tid}' AND user_id = '${uid}' AND org_id = '${globex}'`,
  );
  expect(Number(sessions)).toBeGreaterThan(0);
});

test("one organization is chosen silently and shown in the account console", async ({ page }) => {
  cleanUp();
  const uid = userId();
  const only = makeOrg("solo-e2e", "Solo (e2e)");
  join(only, uid);

  await loginWithPassword(page, state);
  // No question: the flow goes straight through to the application.
  await finishAuthorization(page);

  await accountSignIn(page, "/account/organizations/", "Organizations");
  await expect(page.getByText("Solo (e2e)")).toBeVisible();
  await expectAccessible(page);
});

/**
 * Phase 12.2: `ridm:org-admin` granted *inside* one organization. The console
 * then opens that organization and nothing else: no tenant pages, no list of
 * the tenant's other organizations, and members arrive by invitation.
 */
test("an organization's administrator sees only their own organization", async ({ page }) => {
  cleanUp();
  const who = await registerVerifiedUser(state.client_id, state.ui, "org-admin");
  const uid = tenantSql(
    `SELECT id FROM users WHERE tenant_id = '${tid}' AND email = '${who.email}'`,
  );
  const acme = makeOrg("acme-admin-e2e", "Acme Admin (e2e)");
  makeOrg("other-e2e", "Other (e2e)");
  join(acme, uid);
  const role = tenantSql(
    `SELECT id FROM roles WHERE tenant_id = '${tid}' AND client_id IS NULL AND name = 'ridm:org-admin'`,
  );
  tenantSql(
    `INSERT INTO role_assignments (tenant_id, role_id, user_id, org_id)
     VALUES ('${tid}', '${role}', '${uid}', '${acme}') ON CONFLICT DO NOTHING`,
  );
  clearRolesVersion(tid);

  await consoleLogin(page, { ...state, email: who.email, password: who.password });

  // The sidebar carries the organization and only the pages they may open.
  await expect(page.getByRole("link", { name: "Organizations" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Users" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Settings" })).toHaveCount(0);
  await expect(page.getByText("Acme Admin (e2e)").first()).toBeVisible();

  await page.getByRole("link", { name: "Organizations" }).click();
  await expect(page.getByRole("heading", { name: "Acme Admin (e2e)", level: 1 })).toBeVisible({
    timeout: 15_000,
  });
  // Their own organization, opened directly: no list of the tenant's others.
  await expect(page.getByText("Other (e2e)")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "New organization" })).toHaveCount(0);
  await expect(page.getByLabel("Slug")).toBeDisabled();
  await expect(page.getByLabel("Name")).toBeEnabled();
  await expect(page.getByRole("button", { name: "Add member" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Invitations" })).toBeVisible();
  await expectAccessible(page);

  // An invitation is how they add people, and it carries the organization.
  const invitee = `invited-${Date.now()}@example.com`;
  await page.getByLabel("Email address to invite").fill(invitee);
  await page.getByRole("button", { name: "Invite" }).click();
  await expect(page.getByText(invitee)).toBeVisible({ timeout: 15_000 });
  const carried = tenantSql(
    `SELECT count(*) FROM invitations WHERE tenant_id = '${tid}' AND email = '${invitee}' AND org_id = '${acme}'`,
  );
  expect(Number(carried)).toBe(1);
  tenantSql(`DELETE FROM invitations WHERE tenant_id = '${tid}' AND email = '${invitee}'`);
});
