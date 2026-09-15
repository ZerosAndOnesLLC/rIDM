"use client";

import { useEffect, useRef } from "react";

export interface ShortcutHandlers {
  /** ⌘K / Ctrl+K, or `/` outside a field. */
  palette: () => void;
  /** `t` outside a field (global administrators). */
  tenants?: () => void;
  /** `?` outside a field. */
  help: () => void;
  /** `g` then a key, outside a field. */
  go: (key: string) => boolean;
}

/** Keys that typing fields own; single-key shortcuts stay out of their way. */
function inField(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
}

const SEQUENCE_MS = 1000;

/**
 * Console-wide keyboard shortcuts. Modifier combinations work everywhere;
 * single keys only when no field has focus. `g` starts a one-second
 * sequence (`g o` opens the overview).
 */
export function useShortcuts(handlers: ShortcutHandlers) {
  const ref = useRef(handlers);
  useEffect(() => {
    ref.current = handlers;
  });
  const pendingG = useRef<number | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const h = ref.current;
      if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        h.palette();
        return;
      }
      if (e.ctrlKey || e.metaKey || e.altKey || inField(e.target)) return;
      if (pendingG.current !== null) {
        window.clearTimeout(pendingG.current);
        pendingG.current = null;
        if (h.go(e.key.toLowerCase())) {
          e.preventDefault();
          return;
        }
      }
      switch (e.key) {
        case "/":
          e.preventDefault();
          h.palette();
          break;
        case "?":
          e.preventDefault();
          h.help();
          break;
        case "t":
          if (h.tenants) {
            e.preventDefault();
            h.tenants();
          }
          break;
        case "g":
          pendingG.current = window.setTimeout(() => {
            pendingG.current = null;
          }, SEQUENCE_MS);
          break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}

/** `⌘` on Apple platforms, `Ctrl` elsewhere, for shortcut labels. */
export function modKey(): string {
  if (typeof navigator === "undefined") return "Ctrl";
  return /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘" : "Ctrl";
}
