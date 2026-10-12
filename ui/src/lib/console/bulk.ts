import type { ToastOptions } from "@/components/base/toast";

export interface BulkResult {
  ok: number;
  failed: number;
  /** The first few failures, for the toast. */
  errors: string[];
}

/**
 * Runs `fn` for every item at once and waits for all of them, whatever
 * happens to each (`Promise.allSettled`): a bulk action never stops
 * halfway because one row refused.
 */
export async function runBulk<T>(items: readonly T[], fn: (item: T) => Promise<unknown>): Promise<BulkResult> {
  const results = await Promise.allSettled(items.map((i) => fn(i)));
  const errors = results.flatMap((r) => (r.status === "rejected" ? [r.reason instanceof Error ? r.reason.message : String(r.reason)] : []));
  return { ok: results.length - errors.length, failed: errors.length, errors: errors.slice(0, 3) };
}

/** One toast for the whole run: "3 users disabled", or "2 of 3 users deleted" with why the rest failed. */
export function bulkToast(result: BulkResult, verb: string, noun: [string, string]): ToastOptions {
  const total = result.ok + result.failed;
  const what = total === 1 ? noun[0] : noun[1];
  if (result.failed === 0) return { title: `${total} ${what} ${verb}`, tone: "ok" };
  return {
    title: `${result.ok} of ${total} ${what} ${verb}`,
    description: `${result.failed} failed: ${[...new Set(result.errors)].join("; ")}`,
    tone: result.ok === 0 ? "error" : "info",
    duration: 10_000,
  };
}
