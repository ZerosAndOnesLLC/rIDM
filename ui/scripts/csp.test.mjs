import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { buildPolicy, injectMeta, inlineScriptHashes, originOf, run } from "./csp.mjs";

const sha = (s) => `'sha256-${createHash("sha256").update(s, "utf8").digest("base64")}'`;

test("hashes executable inline scripts only", () => {
  const html =
    `<head><script src="/a.js"></script><script>alert(1)</script>` +
    `<script type="application/json">{"x":1}</script><script type="module">import "./m.js"</script>` +
    `<script>alert(1)</script><script>  </script></head>`;
  assert.deepEqual(inlineScriptHashes(html), [sha("alert(1)"), sha('import "./m.js"')]);
});

test("policy allows self, the hashes, the API and the captcha vendors", () => {
  const p = buildPolicy({ hashes: [sha("x")], apiOrigin: "https://id.example.com" });
  assert.match(p, /script-src 'self' 'sha256-[A-Za-z0-9+/=]+' https:\/\/challenges\.cloudflare\.com/);
  assert.match(p, /connect-src 'self' https:\/\/id\.example\.com/);
  assert.match(p, /form-action 'self' https:\/\/id\.example\.com/);
  assert.match(p, /object-src 'none'/);
  assert.match(p, /base-uri 'self'/);
  assert.doesNotMatch(p, /unsafe-eval/);
  assert.doesNotMatch(p, /script-src[^;]*'unsafe-inline'/);
  assert.match(buildPolicy({ hashes: [], apiOrigin: null }), /connect-src 'self' https:/);
});

test("only the logout page may frame a relying party", () => {
  const plain = buildPolicy({ hashes: [], apiOrigin: "https://id.example.com" });
  assert.match(plain, /frame-src https:\/\/challenges\.cloudflare\.com https:\/\/\*\.hcaptcha\.com;/);
  // Front-channel logout loads each client's logout URI in a hidden iframe.
  const logout = buildPolicy({ hashes: [], apiOrigin: "https://id.example.com", framesRelyingParties: true });
  assert.match(logout, /frame-src [^;]*https:;/);
  assert.doesNotMatch(logout, /frame-src [^;]*http:;/);
  // A deployment served over plain http (development) frames those too.
  const dev = buildPolicy({ hashes: [], apiOrigin: "http://localhost:8090", framesRelyingParties: true });
  assert.match(dev, /frame-src [^;]*https: http:;/);
});

test("origin of the API url", () => {
  assert.equal(originOf("https://id.example.com/base/"), "https://id.example.com");
  assert.equal(originOf(""), null);
  assert.equal(originOf("nonsense"), null);
});

test("meta tag becomes the first head element and replaces an older one", () => {
  const html = `<!DOCTYPE html><html><head><meta charSet="utf-8"/><script>x()</script></head><body></body></html>`;
  const once = injectMeta(html, "default-src 'self'");
  assert.match(once, /<head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"><meta charSet/);
  const twice = injectMeta(once, "default-src 'none'");
  assert.equal((twice.match(/Content-Security-Policy/g) ?? []).length, 1);
  assert.match(twice, /content="default-src 'none'"/);
  assert.throws(() => injectMeta("<html></html>", "x"), /no <head>/);
});

test("run processes every page and hashes each page's own scripts", async () => {
  const dir = await mkdtemp(join(tmpdir(), "csp-"));
  await mkdir(join(dir, "login"), { recursive: true });
  await writeFile(join(dir, "index.html"), `<html><head></head><body><script>a()</script></body></html>`);
  await writeFile(join(dir, "login", "index.html"), `<html><head></head><body><script>b()</script></body></html>`);
  await writeFile(join(dir, "notes.txt"), "not html");
  assert.equal(await run(dir, "http://localhost:8090"), 2);
  const login = await readFile(join(dir, "login", "index.html"), "utf8");
  assert.match(login, new RegExp(sha("b()").replaceAll("+", "\\+")));
  assert.doesNotMatch(login, new RegExp(sha("a()").replaceAll("+", "\\+")));
  assert.match(login, /connect-src 'self' http:\/\/localhost:8090/);
});
