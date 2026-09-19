import { readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { expect, test } from "@playwright/test";

// Embedded UI mode: the API serves the static export itself. Every page in
// src/app must answer at its directory URL with its own HTML and client
// payload, redirect there from the slash-less URL keeping the query, and
// every build asset it references must resolve and be cached for good. The
// routes come from the source tree, so a page missing from the export fails
// here. Only meaningful against the embedded build (CI sets E2E_UI_URL); under
// `next dev` the trailing-slash redirect is off.
test.skip(!process.env.E2E_UI_URL, "embedded UI mode only (set E2E_UI_URL to the API)");

const APP = join(__dirname, "..", "src", "app");

function pageRoutes(dir: string): string[] {
  const routes: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) routes.push(...pageRoutes(path));
    else if (entry.name === "page.tsx") {
      const rel = relative(APP, dir).split(sep).filter(Boolean).join("/");
      routes.push(rel ? `/${rel}/` : "/");
    }
  }
  return routes;
}

const ROUTES = pageRoutes(APP).sort();

test("the source tree has pages to check", () => {
  expect(ROUTES).toContain("/");
  expect(ROUTES).toContain("/login/");
  expect(ROUTES).toContain("/console/users/");
  expect(ROUTES).toContain("/account/security/");
});

test("every page is served at its trailing-slash URL", async ({ request }) => {
  const assets = new Set<string>();
  for (const route of ROUTES) {
    const res = await request.get(route, { maxRedirects: 0 });
    expect(res.status(), route).toBe(200);
    expect(res.headers()["content-type"], route).toMatch(/^text\/html/);
    expect(res.headers()["cache-control"], route).toBe("no-cache");
    const html = await res.text();
    expect(html, route).toContain("<html");
    for (const [, asset] of html.matchAll(/(?:src|href)="(\/_next\/static\/[^"?#]+)"/g)) {
      if (asset) assets.add(asset);
    }

    // The payload client-side navigation fetches beside the page.
    const payload = await request.get(`${route}index.txt`, { maxRedirects: 0 });
    expect(payload.status(), `${route}index.txt`).toBe(200);

    if (route !== "/") {
      const bare = route.slice(0, -1);
      const redirect = await request.get(`${bare}?probe=1&x=a%2Fb`, { maxRedirects: 0 });
      expect(redirect.status(), bare).toBe(308);
      expect(redirect.headers()["location"], bare).toBe(`${route}?probe=1&x=a%2Fb`);
    }
  }

  expect(assets.size).toBeGreaterThan(0);
  for (const asset of assets) {
    const res = await request.get(asset, { maxRedirects: 0 });
    expect(res.status(), asset).toBe(200);
    expect(res.headers()["cache-control"], asset).toContain("immutable");
  }
});

test("a path that is no page gets the export's 404", async ({ request }) => {
  for (const path of ["/no-such-page/", "/console/no-such-page/", "/login/no-such-file.js"]) {
    const res = await request.get(path, { maxRedirects: 0 });
    expect(res.status(), path).toBe(404);
    expect(res.headers()["content-type"], path).toMatch(/^text\/html/);
  }
});
