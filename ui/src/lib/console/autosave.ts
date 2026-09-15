"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type SaveStatus = "idle" | "pending" | "saving" | "saved" | "error";

/** Recursive merge of two JSON merge patches: the later one wins, `null` included. */
export function mergePatches(a: unknown, b: unknown): unknown {
  if (!isObject(a) || !isObject(b)) return b;
  const out: Record<string, unknown> = { ...a };
  for (const [k, v] of Object.entries(b)) out[k] = k in out ? mergePatches(out[k], v) : v;
  return out;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export interface SaveOptions {
  /** The page is going away: the request must outlive it. */
  keepalive?: boolean;
}

/**
 * Auto-save for forms: changes are queued as merge patches, coalesced, and
 * sent once typing pauses (`delay`), or after `maxDelay` of continuous
 * editing at the latest. A save that fails reports its message and drops
 * the batch, so the caller reloads the stored state. Unsent changes are
 * flushed with `keepalive` when the page is hidden or unloaded.
 */
export function useAutoSave<P>(save: (patch: P, options: SaveOptions) => Promise<void>, delay = 600, maxDelay = 2500) {
  const [status, setStatus] = useState<SaveStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const pending = useRef<P | null>(null);
  const timer = useRef<number | null>(null);
  const deadline = useRef<number | null>(null);
  const inFlight = useRef<Promise<void> | null>(null);
  const saveRef = useRef(save);
  useEffect(() => {
    saveRef.current = save;
  });

  const flush = useCallback(async (options: SaveOptions = {}) => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
    deadline.current = null;
    if (inFlight.current) await inFlight.current;
    const batch = pending.current;
    if (batch === null) return;
    pending.current = null;
    setStatus("saving");
    inFlight.current = saveRef
      .current(batch, options)
      .then(() => {
        setError(null);
        setStatus("saved");
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : String(e));
        setStatus("error");
      })
      .finally(() => {
        inFlight.current = null;
      });
    await inFlight.current;
  }, []);

  const queue = useCallback(
    (patch: P) => {
      pending.current = pending.current === null ? patch : (mergePatches(pending.current, patch) as P);
      setStatus("pending");
      const now = Date.now();
      deadline.current ??= now + maxDelay;
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(
        () => {
          timer.current = null;
          void flush();
        },
        Math.max(0, Math.min(delay, deadline.current - now)),
      );
    },
    [delay, maxDelay, flush],
  );

  useEffect(() => {
    const onHide = () => {
      if (document.visibilityState === "hidden") void flush({ keepalive: true });
    };
    const onUnload = () => void flush({ keepalive: true });
    document.addEventListener("visibilitychange", onHide);
    window.addEventListener("pagehide", onUnload);
    return () => {
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", onUnload);
    };
  }, [flush]);

  useEffect(() => {
    if (status !== "saved") return;
    const t = window.setTimeout(() => setStatus((s) => (s === "saved" ? "idle" : s)), 2500);
    return () => window.clearTimeout(t);
  }, [status]);

  return { queue, flush, status, error };
}
