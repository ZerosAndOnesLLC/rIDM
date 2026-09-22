import { chromium, expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { alertOf, authorizeUrl, clearTenantCache, consoleLogin, expectAccessible, finishAuthorization, loadState, tenantId, tenantSql, TENANT } from "./helpers";

/**
 * Kerberos / SPNEGO desktop sign-in (Phase 13.4), with a real MIT KDC in a
 * container (the same image as the API's `kerberos_mit` test): an
 * administrator creates the realm from the keytab the KDC exported; a
 * browser without a ticket gets the usual login page; a Chromium holding a
 * ticket (its GSSAPI pointed at the KDC, `localhost` on its allowlist)
 * signs in on its own, the way a domain-joined desktop does.
 */

const RUN = randomBytes(4).toString("hex");
const KDC = `ridm-e2e-kdc-${RUN}`;
const KDC_PORT = process.env.E2E_KDC_PORT ?? "18088";
const IMAGE = "ridm-test-kdc:1";
const DOCKERFILE = `FROM debian:bookworm-slim
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server krb5-user python3-gssapi \\
 && rm -rf /var/lib/apt/lists/*
`;
const USER = `kira-${RUN}`;
const ALIAS = `windows-${RUN}`;
const NAME = "Windows sign-in";
const DIR = join(tmpdir(), KDC);

const SETUP = `set -e
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
  default_realm = EXAMPLE.TEST
  dns_canonicalize_hostname = false
  rdns = false
[realms]
  EXAMPLE.TEST = {
    kdc = 127.0.0.1
  }
EOF
kdb5_util create -s -r EXAMPLE.TEST -P master-pw >/dev/null
kadmin.local -q "addprinc -pw Kira-Krb-Pw1 ${USER}" >/dev/null
kadmin.local -q "addprinc -randkey -e aes256-cts-hmac-sha1-96:normal HTTP/localhost" >/dev/null
kadmin.local -q "ktadd -norandkey -k /tmp/http.keytab HTTP/localhost" >/dev/null
krb5kdc
echo Kira-Krb-Pw1 | kinit -c FILE:/tmp/cc ${USER} >/dev/null
touch /tmp/ready
exec sleep infinity
`;

function docker(args: string[], input?: string): string {
  return execFileSync("docker", args, { encoding: "utf8", input }).trim();
}

test.describe("Kerberos desktop sign-in", () => {
  test.describe.configure({ mode: "serial" });

  test.beforeAll(async () => {
    test.setTimeout(300_000);
    try {
      docker(["image", "inspect", IMAGE]);
    } catch {
      docker(["build", "-q", "-t", IMAGE, "-"], DOCKERFILE);
    }
    docker(["run", "-d", "--name", KDC, "-p", `127.0.0.1:${KDC_PORT}:88/tcp`, IMAGE, "sh", "-c", SETUP]);
    for (let i = 0; ; i++) {
      try {
        docker(["exec", KDC, "test", "-f", "/tmp/ready"]);
        break;
      } catch {
        if (i > 60) throw new Error(`the KDC did not come up: ${docker(["logs", KDC])}`);
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    mkdirSync(DIR, { recursive: true });
    docker(["cp", `${KDC}:/tmp/http.keytab`, join(DIR, "http.keytab")]);
    docker(["cp", `${KDC}:/tmp/cc`, join(DIR, "cc")]);
    writeFileSync(
      join(DIR, "krb5.conf"),
      `[libdefaults]
  default_realm = EXAMPLE.TEST
  dns_lookup_kdc = false
  dns_lookup_realm = false
  dns_canonicalize_hostname = false
  rdns = false
  # MIT 1.20+ appends the resolver's search domain to a short name such as
  # localhost (CI runners have one), which names a principal nobody has.
  qualify_shortname = ""
  udp_preference_limit = 1
[realms]
  EXAMPLE.TEST = {
    kdc = 127.0.0.1:${KDC_PORT}
  }
[domain_realm]
  localhost = EXAMPLE.TEST
`,
    );
  });

  test.afterAll(() => {
    try {
      docker(["rm", "-f", KDC]);
    } catch {
      // Already gone.
    }
    rmSync(DIR, { recursive: true, force: true });
    const tid = tenantId();
    tenantSql(`DELETE FROM identity_providers WHERE tenant_id = '${tid}' AND alias = '${ALIAS}'`);
    tenantSql(`DELETE FROM users WHERE tenant_id = '${tid}' AND username = '${USER}'`);
    clearTenantCache();
  });

  test("an administrator adds a realm from its keytab", async ({ page }) => {
    await consoleLogin(page, loadState());
    await page.goto(`/console/identity-providers/?tenant=${TENANT}`);
    await expect(page.getByRole("heading", { name: "Identity providers", level: 1 })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New provider" }).click();
    const dialog = page.getByRole("dialog", { name: "New identity provider" });
    await dialog.getByLabel("Preset").selectOption("kerberos");
    await dialog.getByLabel("Alias").fill(ALIAS);
    await dialog.getByLabel("Display name").fill(NAME);
    await dialog.locator('input[type="file"]').setInputFiles(join(DIR, "http.keytab"));
    await expect(dialog.getByText("AES keys for HTTP/localhost@EXAMPLE.TEST")).toBeVisible({ timeout: 15_000 });
    // The browser reaches the API over loopback, IPv4 or IPv6.
    const networks = dialog.getByLabel("Trusted networks");
    await networks.fill("127.0.0.0/8 ::1/128");
    await networks.press("Enter");
    await expect(dialog.getByLabel("Client ID")).toHaveCount(0);
    await expectAccessible(page);
    await dialog.getByRole("button", { name: "Create provider" }).click();
    await expect(page.getByRole("heading", { name: NAME, level: 2 })).toBeVisible({ timeout: 15_000 });

    // The keytab is described, never shown; there is no callback URL.
    await expect(page.getByText("HTTP/localhost@EXAMPLE.TEST", { exact: true })).toBeVisible();
    await expect(page.getByText(/aes256-cts-hmac-sha1-96/).first()).toBeVisible();
    await expect(page.getByText("Register this redirect URI with the provider.")).toHaveCount(0);
    await expect(page.getByLabel("Service principal")).toHaveValue("HTTP/localhost@EXAMPLE.TEST");

    // Principals no account matches get one (auto-saved).
    await page.getByRole("switch", { name: "Create accounts" }).click();
    await expect(page.getByText(/^Saved$/)).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page);
  });

  test("a browser without a ticket gets the usual login page", async ({ page }) => {
    const s = loadState();
    await page.goto(authorizeUrl(s));
    await page.waitForURL(/\/login\//);
    // The automatic attempt found no ticket: nothing to say, the form stays.
    await expect(page.getByText("Checking for your desktop sign-in…")).toHaveCount(0, { timeout: 15_000 });
    await expect(page.getByLabel("Email or username")).toBeVisible();
    await expect(alertOf(page)).toHaveCount(0);
    // Asked explicitly, it says why nothing happened.
    await page.getByRole("button", { name: `Continue with ${NAME}` }).click();
    await expect(alertOf(page)).toContainText("did not offer a Kerberos ticket", { timeout: 15_000 });
    await expectAccessible(page);
  });

  test("a desktop holding a ticket signs in on its own", async () => {
    const s = loadState();
    // Chromium's GSSAPI (MIT's libgssapi_krb5) reads this configuration and
    // ticket cache; localhost is the only server it negotiates with.
    const browser = await chromium.launch({
      args: ["--auth-server-allowlist=localhost", "--disable-auth-negotiate-cname-lookup"],
      env: { ...process.env, KRB5_CONFIG: join(DIR, "krb5.conf"), KRB5CCNAME: `FILE:${join(DIR, "cc")}`, KRB5_TRACE: join(DIR, "trace.log") },
    });
    try {
      const context = await browser.newContext({ baseURL: s.ui });
      const page = await context.newPage();
      // What the Kerberos step answered, and what MIT's library did, to
      // say why when the sign-in does not happen.
      const answers: string[] = [];
      page.on("response", (r) => {
        if (r.url().endsWith("/kerberos")) answers.push(`${r.status()} ${r.request().headers()["authorization"] ? "with a token" : "without a token"}`);
      });
      await page.goto(authorizeUrl(s));
      // No typing: the login page negotiates, rIDM accepts the ticket and
      // creates the account; the tenant's terms come next for a new one.
      try {
        await expect(page.getByRole("heading", { name: "Terms of service" })).toBeVisible({ timeout: 20_000 });
      } catch (e) {
        const trace = existsSync(join(DIR, "trace.log")) ? readFileSync(join(DIR, "trace.log"), "utf8").slice(-4000) : "no GSSAPI trace (the library was not used)";
        throw new Error(`${e}\nKerberos step answers: ${answers.join(", ") || "none"}\n${trace}`);
      }
      await page.getByRole("checkbox").check();
      await page.getByRole("button", { name: "I accept" }).click();
      await finishAuthorization(page);
      const tid = tenantId();
      expect(tenantSql(`SELECT count(*) FROM users WHERE tenant_id = '${tid}' AND username = '${USER}' AND password_hash IS NULL`)).toBe("1");
      expect(
        tenantSql(
          `SELECT f.external_subject FROM federated_identities f JOIN identity_providers p ON p.tenant_id = f.tenant_id AND p.id = f.idp_id WHERE f.tenant_id = '${tid}' AND p.alias = '${ALIAS}'`,
        ),
      ).toBe(`${USER}@EXAMPLE.TEST`);
      await context.close();
    } finally {
      await browser.close();
    }
  });
});
