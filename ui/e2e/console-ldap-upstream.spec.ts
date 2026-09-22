import { expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { authorizeUrl, clearTenantCache, consoleLogin, expectAccessible, finishAuthorization, loadState, tenantId, tenantSql, TENANT } from "./helpers";

/**
 * LDAP / Active Directory upstream (Phase 13.3), against an OpenLDAP the
 * suite seeds with `ldapadd`: an administrator adds the directory in the
 * console, tests the connection, turns group sync on and syncs; a directory
 * user then signs in with the ordinary password form.
 */

const LDAP_URL = process.env.E2E_LDAP_URL ?? "ldap://127.0.0.1:1389";
const ADMIN_DN = "cn=admin,dc=example,dc=org";
const ADMIN_PASSWORD = process.env.E2E_LDAP_ADMIN_PASSWORD ?? "admin-Passw0rd";
const RUN = randomBytes(4).toString("hex");
const BASE = `ou=e2e-${RUN},dc=example,dc=org`;
const USER = `lena-${RUN}`;
const GROUP = `e2e-staff-${RUN}`;
const PASSWORD = "Lena-Directory-Pw1";
const ALIAS = `ldap-${RUN}`;
const NAME = "Corp Directory";

function ldapadd(ldif: string) {
  execFileSync("ldapadd", ["-x", "-H", LDAP_URL, "-D", ADMIN_DN, "-w", ADMIN_PASSWORD], { input: ldif, encoding: "utf8" });
}

test.describe("LDAP directory upstream", () => {
  test.describe.configure({ mode: "serial" });

  test.beforeAll(() => {
    ldapadd(
      [
        `dn: ${BASE}\nobjectClass: organizationalUnit\nou: e2e-${RUN}\n`,
        `dn: ou=people,${BASE}\nobjectClass: organizationalUnit\nou: people\n`,
        `dn: ou=groups,${BASE}\nobjectClass: organizationalUnit\nou: groups\n`,
        `dn: uid=${USER},ou=people,${BASE}\nobjectClass: inetOrgPerson\nuid: ${USER}\ncn: Lena\nsn: Tester\nmail: ${USER}@corp.example\nuserPassword: ${PASSWORD}\n`,
        `dn: cn=${GROUP},ou=groups,${BASE}\nobjectClass: groupOfNames\ncn: ${GROUP}\nmember: uid=${USER},ou=people,${BASE}\n`,
      ].join("\n"),
    );
  });

  test.afterAll(() => {
    const tid = tenantId();
    tenantSql(`DELETE FROM identity_providers WHERE tenant_id = '${tid}' AND alias = '${ALIAS}'`);
    tenantSql(`DELETE FROM users WHERE tenant_id = '${tid}' AND username = '${USER}'`);
    tenantSql(`DELETE FROM groups WHERE tenant_id = '${tid}' AND name = '${GROUP}'`);
    clearTenantCache();
  });

  test("an administrator adds a directory, tests it and syncs it", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/identity-providers/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Identity providers", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New provider" }).click();
    const dialog = page.getByRole("dialog", { name: "New identity provider" });
    await dialog.getByLabel("Preset").selectOption("ldap");
    await dialog.getByLabel("Alias").fill(ALIAS);
    await dialog.getByLabel("Display name").fill(NAME);
    await dialog.getByLabel("Server").selectOption("openldap");
    await dialog.getByLabel("URL", { exact: true }).fill(LDAP_URL);
    await dialog.getByLabel("Users DN").fill(`ou=people,${BASE}`);
    await dialog.getByLabel("Bind DN").fill(ADMIN_DN);
    await dialog.getByLabel("Bind password").fill(ADMIN_PASSWORD);
    await expect(dialog.getByLabel("Client ID")).toHaveCount(0);
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Create provider" }).click();
    await expect(page.getByRole("heading", { name: NAME, level: 2 })).toBeVisible({ timeout: 15_000 });

    // The vendor's defaults were filled in; a directory has no callback URL.
    await expect(page.getByLabel("Username attribute", { exact: true }).first()).toHaveValue("uid");
    await expect(page.getByLabel("UUID attribute")).toHaveValue("entryUUID");
    await expect(page.getByText("Register this redirect URI with the provider.")).toHaveCount(0);

    await page.getByRole("button", { name: "Test connection" }).click();
    await expect(page.getByText("service account bound")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(USER)).toBeVisible();

    // Group sync on (auto-saved), then a full sync imports the user and the group.
    await page.getByLabel("Groups DN").fill(`ou=groups,${BASE}`);
    await expect(page.getByText(/^Saved$/)).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Full sync" }).click();
    await expect(page.getByText(/^Full: 1 read, 1 created/)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/^Last synced /)).toBeVisible();
    await expectAccessible(page);
  });

  test("a directory user signs in with the password form", async ({ page }) => {
    const s = loadState();
    await page.goto(authorizeUrl(s, { prompt: "login" }));
    await page.waitForURL(/\/login\//);
    // A directory is no button on the login page.
    await expect(page.getByRole("button", { name: `Continue with ${NAME}` })).toHaveCount(0);
    await page.getByLabel("Email or username").fill(USER);
    await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    // Signed in by the directory; the tenant's terms come next for a new account.
    await expect(page.getByRole("heading", { name: "Terms of service" })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "I accept" }).click();
    await finishAuthorization(page);
    expect(tenantSql(`SELECT password_hash IS NULL FROM users WHERE tenant_id = '${tenantId()}' AND username = '${USER}'`)).toBe("t");
  });
});
