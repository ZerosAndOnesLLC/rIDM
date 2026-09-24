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

function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((v, i) => sameJson(v, b[i]));
  if (isObject(a) && isObject(b)) {
    const ka = Object.keys(a);
    return ka.length === Object.keys(b).length && ka.every((k) => k in b && sameJson(a[k], b[k]));
  }
  return false;
}

/**
 * `patch` without the top-level fields `base` already holds exactly; a
 * `null` for a field `base` lacks is a no-op too. Only whole fields are
 * compared: several endpoints replace a nested value (profile attributes,
 * JSON attributes) as a whole, so a field is sent complete or not at all.
 * `undefined` when nothing is left.
 */
export function prunePatch(patch: unknown, base: unknown): unknown {
  if (!isObject(patch) || !isObject(base)) return patch;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(patch)) {
    const stored = base[k];
    if (v === null && (stored === undefined || stored === null)) continue;
    if (stored !== undefined && sameJson(v, stored)) continue;
    out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
}

export interface AutoSaveOptions {
  /**
   * The record as stored, in the shape patches are written in. Changes that
   * would leave it as it is are not sent (a field typed and put back, the
   * same value chosen again). Omitted: every queued change is sent.
   */
  baseline?: unknown;
  /** Quiet time after the last change before saving (ms). */
  delay?: number;
  /** Longest a change waits during continuous editing (ms). */
  maxDelay?: number;
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
 * flushed with `keepalive` when the page is hidden or unloaded, and when
 * the editor unmounts, so an edit made just before switching records
 * still lands on the record it was made on. Editors are keyed by record
 * id for that reason: a new record means a new instance and a new queue.
 */
export function useAutoSave<P>(save: (patch: P, options: SaveOptions) => Promise<void>, { baseline, delay = 600, maxDelay = 2500 }: AutoSaveOptions = {}) {
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
  // The stored state as last known: the baseline the caller passed, with
  // the fields of every save since (the caller's refetch catches up later).
  const confirmed = useRef<unknown>(baseline);
  useEffect(() => {
    confirmed.current = baseline;
  }, [baseline]);

  const flush = useCallback(async (options: SaveOptions = {}) => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
    deadline.current = null;
    if (inFlight.current) await inFlight.current;
    const queued = pending.current;
    if (queued === null) return;
    pending.current = null;
    const batch = (confirmed.current === undefined ? queued : prunePatch(queued, confirmed.current)) as P | undefined;
    if (batch === undefined) {
      // Everything queued is already stored: nothing to send.
      setStatus((s) => (s === "pending" ? "idle" : s));
      return;
    }
    setStatus("saving");
    inFlight.current = saveRef
      .current(batch, options)
      .then(() => {
        // Whole fields, as `prunePatch` compares them: what was sent is now
        // what is stored for each field it named.
        if (isObject(confirmed.current) && isObject(batch)) confirmed.current = { ...confirmed.current, ...batch };
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

  useEffect(() => () => void flush(), [flush]);

  useEffect(() => {
    if (status !== "saved") return;
    const t = window.setTimeout(() => setStatus((s) => (s === "saved" ? "idle" : s)), 2500);
    return () => window.clearTimeout(t);
  }, [status]);

  return { queue, flush, status, error };
}
