/**
 * A reading of a User-Agent string for session and device rows: which
 * browser, on what, roughly. Substring checks in the order the strings
 * impersonate each other (Edge and Opera say "Chrome", everything says
 * "Safari"), nothing more: it is a label, not a fingerprint.
 */
export interface Agent {
  browser: string | null;
  os: string | null;
  device: "phone" | "tablet" | "desktop" | "bot" | null;
}

const BROWSERS: [RegExp, string][] = [
  [/\bEdg(?:e|A|iOS)?\//, "Edge"],
  [/\bOPR\/|\bOpera\b/, "Opera"],
  [/\bSamsungBrowser\//, "Samsung Internet"],
  [/\bVivaldi\//, "Vivaldi"],
  [/\bBrave\//, "Brave"],
  [/\bDuckDuckGo\//, "DuckDuckGo"],
  [/\bFirefox\/|\bFxiOS\//, "Firefox"],
  [/\bChrome\/|\bCriOS\/|\bChromium\//, "Chrome"],
  [/\bVersion\/[\d.]+.*\bSafari\//, "Safari"],
  [/\bSafari\//, "Safari"],
  [/\bMSIE\b|\bTrident\//, "Internet Explorer"],
];

const BOTS = /\b(bot|crawler|spider|curl|wget|python-requests|Go-http-client|okhttp|HeadlessChrome|Playwright)\b/i;

const SYSTEMS: [RegExp, string][] = [
  [/\biPhone\b/, "iPhone"],
  [/\biPad\b/, "iPad"],
  [/\bAndroid\b/, "Android"],
  [/\bWindows Phone\b/, "Windows Phone"],
  [/\bWindows\b/, "Windows"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bMac OS X\b|\bMacintosh\b/, "macOS"],
  [/\bLinux\b|\bX11\b/, "Linux"],
];

export function parseUserAgent(ua: string | null | undefined): Agent {
  if (!ua) return { browser: null, os: null, device: null };
  const bot = BOTS.test(ua);
  const browser = BROWSERS.find(([re]) => re.test(ua))?.[1] ?? null;
  const os = SYSTEMS.find(([re]) => re.test(ua))?.[1] ?? null;
  const device: Agent["device"] = bot
    ? "bot"
    : /\biPad\b|\bTablet\b|(?:\bAndroid\b(?!.*\bMobile\b))/.test(ua)
      ? "tablet"
      : /\bMobile\b|\biPhone\b|\bWindows Phone\b/.test(ua)
        ? "phone"
        : browser || os
          ? "desktop"
          : null;
  return { browser, os, device };
}

/** "Chrome on Linux", "Safari on iPhone", or what little the string gives. */
export function describeAgent(ua: string | null | undefined): string {
  if (!ua) return "Unknown browser";
  const { browser, os } = parseUserAgent(ua);
  if (browser && os) return `${browser} on ${os}`;
  if (browser) return browser;
  if (os) return `Browser on ${os}`;
  // Something that is not a browser (a CLI, a script): its first token.
  const first = ua.split(/[\s/]/)[0];
  return first && first.length <= 40 ? first : "Unknown browser";
}
