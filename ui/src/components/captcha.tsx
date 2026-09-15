"use client";

import { useEffect, useRef } from "react";
import type { CaptchaChallenge } from "@/lib/types";

// Provider globals, loaded on demand from the vendor's script.
declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: { sitekey: string; callback: (token: string) => void; "expired-callback"?: () => void; theme?: string }) => string;
      remove: (id: string) => void;
    };
    hcaptcha?: {
      render: (el: HTMLElement, opts: { sitekey: string; callback: (token: string) => void; "expired-callback"?: () => void }) => string;
      remove: (id: string) => void;
    };
  }
}

const SCRIPTS = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
  hcaptcha: "https://js.hcaptcha.com/1/api.js?render=explicit",
} as const;

type Kind = keyof typeof SCRIPTS;

function kindOf(c: CaptchaChallenge): Kind | null {
  if (c.provider === "turnstile") return "turnstile";
  if (c.provider === "h_captcha" || c.provider === "hcaptcha") return "hcaptcha";
  return null;
}

const loading = new Map<Kind, Promise<void>>();
function load(kind: Kind): Promise<void> {
  let p = loading.get(kind);
  if (!p) {
    p = new Promise<void>((resolve, reject) => {
      if (window[kind]) return resolve();
      const s = document.createElement("script");
      s.src = SCRIPTS[kind];
      s.async = true;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error(`failed to load ${kind}`));
      document.head.appendChild(s);
    });
    loading.set(kind, p);
  }
  return p;
}

/** Renders the tenant's CAPTCHA widget and reports the token to `onToken`. */
export function Captcha({ challenge, onToken }: { challenge: CaptchaChallenge; onToken: (token: string | null) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const kind = kindOf(challenge);

  useEffect(() => {
    if (!kind || !ref.current) return;
    const el = ref.current;
    let widget: string | null = null;
    let cancelled = false;
    load(kind)
      .then(() => {
        if (cancelled) return;
        const provider = window[kind];
        if (!provider) return;
        widget = provider.render(el, {
          sitekey: challenge.site_key,
          callback: (token: string) => onToken(token),
          "expired-callback": () => onToken(null),
        });
      })
      .catch(() => onToken(null));
    return () => {
      cancelled = true;
      if (widget) window[kind]?.remove(widget);
      el.replaceChildren();
    };
  }, [kind, challenge.site_key, onToken]);

  if (!kind) return null;
  return <div ref={ref} className="flex justify-center" />;
}
