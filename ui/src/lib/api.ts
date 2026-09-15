// Minimal fetch wrapper for the rIDM API. Same origin in embedded mode;
// `NEXT_PUBLIC_API_URL` when the UI is hosted separately.

import type { Problem } from "./types";

export const API_BASE = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/+$/, "");

export function tenantBase(slug: string): string {
  return `${API_BASE}/t/${encodeURIComponent(slug)}`;
}

/** Any non-2xx answer. `body` is the parsed JSON when there was one. */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(status: number, body: unknown) {
    super(messageOf(status, body));
    this.status = status;
    this.body = body;
  }
  /** `error` code from an OAuth-style body, or the problem type's last segment. */
  get code(): string | null {
    const b = this.body as { error?: unknown; type?: unknown } | null;
    if (b && typeof b.error === "string") return b.error;
    if (b && typeof b.type === "string") return b.type.split(":").pop() ?? null;
    return null;
  }
  get problem(): Problem | null {
    const b = this.body as Problem | null;
    return b && typeof b === "object" && "status" in b ? b : null;
  }
  fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const e of this.problem?.errors ?? []) out[e.field] = e.message;
    return out;
  }
}

/** Thrown when the server could not be reached at all. */
export class NetworkError extends Error {}

function messageOf(status: number, body: unknown): string {
  const b = body as { error_description?: unknown; detail?: unknown; title?: unknown } | null;
  if (b && typeof b.error_description === "string") return b.error_description;
  if (b && typeof b.detail === "string") return b.detail;
  if (b && typeof b.title === "string") return b.title;
  return `HTTP ${status}`;
}

export interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  signal?: AbortSignal;
}

export async function api<T>(url: string, opts: RequestOptions = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      method: opts.method ?? (opts.body === undefined ? "GET" : "POST"),
      headers: opts.body === undefined ? { Accept: "application/json" } : {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      credentials: "include",
      cache: "no-store",
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new NetworkError(String(e));
  }
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data as T;
}
