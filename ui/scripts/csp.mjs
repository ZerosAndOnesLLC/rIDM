// Adds a hash-based Content-Security-Policy to every exported page.
//
// The static export cannot carry nonces, so every inline script Next.js
// writes (the hydration payloads and the theme boot) is allowed by its
// SHA-256 hash and everything else must come from the page's own origin,
// the API (NEXT_PUBLIC_API_URL) or a CAPTCHA vendor. Styles stay inline
// (React style props and tenant custom CSS). The policy is injected as a
// <meta> tag so it works on any static host; framing rules cannot be set
// from a meta tag, so the host (or the embedded server) still sends
// X-Frame-Options / frame-ancestors, as the README documents.
//
// Runs as `postbuild`; fails the build when a page cannot be processed.

import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const CAPTCHA_SCRIPTS = ["https://challenges.cloudflare.com", "https://js.hcaptcha.com", "https://*.hcaptcha.com"];
const CAPTCHA_FRAMES = ["https://challenges.cloudflare.com", "https://*.hcaptcha.com"];
const CAPTCHA_CONNECT = ["https://challenges.cloudflare.com", "https://*.hcaptcha.com"];

const SCRIPT_RE = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi;

/** `scheme://host[:port]` of a URL, or null when it is empty or unparsable. */
export function originOf(url) {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** SHA-256 CSP sources for the executable inline scripts in `html`. */
export function inlineScriptHashes(html) {
  const hashes = new Set();
  for (const m of html.matchAll(SCRIPT_RE)) {
    const attrs = m[1] ?? "";
    if (/\ssrc\s*=/i.test(attrs)) continue;
    const type = /\stype\s*=\s*["']?([^"'\s>]+)/i.exec(attrs)?.[1]?.toLowerCase();
    if (type && !["module", "text/javascript", "application/javascript"].includes(type)) continue;
    const body = m[2];
    if (body.trim() === "") continue;
    hashes.add(`'sha256-${createHash("sha256").update(body, "utf8").digest("base64")}'`);
  }
  return [...hashes];
}

/**
 * Pages that frame a relying party's own URL. Front-channel logout (OIDC
 * Front-Channel Logout 1.0 §3) signs the user out of every connected
 * application by loading its logout URI in a hidden iframe, and those URIs
 * belong to the tenant's clients, not to this origin.
 */
const FRAMES_RELYING_PARTIES = /(^|\/)logout\/index\.html$/;

/** The policy string for one page. */
export function buildPolicy({ hashes, apiOrigin, framesRelyingParties = false }) {
  const api = apiOrigin ? [apiOrigin] : [];
  const rp = framesRelyingParties ? (apiOrigin?.startsWith("http://") ? ["https:", "http:"] : ["https:"]) : [];
  const directives = [
    ["default-src", ["'self'"]],
    ["script-src", ["'self'", ...hashes, ...CAPTCHA_SCRIPTS]],
    ["style-src", ["'self'", "'unsafe-inline'"]],
    ["img-src", ["'self'", "data:", "blob:", "https:", "http:"]],
    ["font-src", ["'self'", "data:", "https:"]],
    ["connect-src", ["'self'", ...api, ...CAPTCHA_CONNECT]],
    ["frame-src", [...CAPTCHA_FRAMES, ...rp]],
    ["worker-src", ["'self'", "blob:"]],
    ["media-src", ["'self'"]],
    ["manifest-src", ["'self'"]],
    ["object-src", ["'none'"]],
    ["base-uri", ["'self'"]],
    ["form-action", ["'self'", ...api]],
  ];
  return directives.map(([name, values]) => `${name} ${values.join(" ")}`).join("; ");
}

const META_RE = /<meta\s+http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*>/i;

/** `html` with the policy as the first element of <head> (replacing an earlier one). */
export function injectMeta(html, policy) {
  const tag = `<meta http-equiv="Content-Security-Policy" content="${policy.replaceAll('"', "&quot;")}">`;
  const stripped = html.replace(META_RE, "");
  const head = /<head(\s[^>]*)?>/i.exec(stripped);
  if (!head) throw new Error("no <head> element");
  const at = head.index + head[0].length;
  return stripped.slice(0, at) + tag + stripped.slice(at);
}

/** Every `.html` file under `dir`, recursively. */
export async function htmlFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await htmlFiles(path)));
    else if (entry.isFile() && entry.name.endsWith(".html")) out.push(path);
  }
  return out;
}

/** Process every page under `outDir`; returns the number of pages written. */
export async function run(outDir, apiUrl) {
  const apiOrigin = originOf(apiUrl);
  const files = await htmlFiles(outDir);
  if (files.length === 0) throw new Error(`no pages under ${outDir}`);
  for (const file of files) {
    const html = await readFile(file, "utf8");
    const policy = buildPolicy({
      hashes: inlineScriptHashes(html),
      apiOrigin,
      framesRelyingParties: FRAMES_RELYING_PARTIES.test(file.replaceAll("\\", "/")),
    });
    await writeFile(file, injectMeta(html, policy));
  }
  return files.length;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const outDir = process.argv[2] ?? "out";
  run(outDir, process.env.NEXT_PUBLIC_API_URL ?? "")
    .then((n) => console.log(`csp: policy added to ${n} pages`))
    .catch((err) => {
      console.error(`csp: ${err.message}`);
      process.exit(1);
    });
}
