"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, NetworkError, tenantBase } from "./api";
import { navigate } from "./params";
import type { FlowStage, PublicFlow } from "./types";

/** Page that hosts each stage; a page redirects when the stage is not its own. */
export const STAGE_PAGE: Record<FlowStage, string> = {
  authenticate: "login",
  register: "register",
  verify_email: "register",
  password_change: "login",
  mfa: "mfa",
  profile: "login",
  terms: "login",
  consent: "consent",
  done: "login",
};

export function pageUrl(page: string, params: Record<string, string | null | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) q.set(k, v);
  const qs = q.toString();
  return `/${page}/${qs ? `?${qs}` : ""}`;
}

/** `post` as exposed by `useFlow`. */
export type Post = <T = PublicFlow>(step: string, body: Record<string, unknown>) => Promise<T>;

export type FlowError =
  | { kind: "expired" }
  | { kind: "network" }
  | { kind: "api"; error: ApiError };

export function toFlowError(e: unknown): FlowError {
  if (e instanceof NetworkError) return { kind: "network" };
  if (e instanceof ApiError) {
    if (e.status === 404 || e.status === 410 || (e.status === 403 && /csrf/i.test(e.message))) {
      return { kind: "expired" };
    }
    return { kind: "api", error: e };
  }
  return { kind: "network" };
}

interface FlowState {
  flow: PublicFlow | null;
  loading: boolean;
  error: FlowError | null;
}

/**
 * Loads a login flow and exposes `post` for its steps. Every successful step
 * answers with the new public state; `done` redirects to `finish_url`, and
 * stages hosted by another page redirect there.
 */
export function useFlow(slug: string | null, id: string | null, accepts: readonly FlowStage[]) {
  const [state, setState] = useState<FlowState>({ flow: null, loading: true, error: null });
  const base = slug ? tenantBase(slug) : null;
  const flowUrl = base && id ? `${base}/flows/${encodeURIComponent(id)}` : null;
  const redirected = useRef(false);

  const accept = useCallback(
    (flow: PublicFlow) => {
      if (flow.stage === "done" && flow.finish_url) {
        redirected.current = true;
        navigate(flow.finish_url);
        return;
      }
      if (!accepts.includes(flow.stage)) {
        redirected.current = true;
        navigate(pageUrl(STAGE_PAGE[flow.stage], { tenant: slug, flow: flow.id }));
        return;
      }
      setState({ flow, loading: false, error: null });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `accepts` is a literal per page
    [slug],
  );

  useEffect(() => {
    if (!flowUrl) {
      setState({ flow: null, loading: false, error: { kind: "expired" } });
      return;
    }
    const ctrl = new AbortController();
    api<PublicFlow>(flowUrl, { signal: ctrl.signal })
      .then(accept)
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        setState({ flow: null, loading: false, error: toFlowError(e) });
      });
    return () => ctrl.abort();
  }, [flowUrl, accept]);

  /** POST a step. Resolves with the new state, or the JSON of a non-state answer. */
  const post = useCallback(
    async <T = PublicFlow,>(step: string, body: Record<string, unknown>): Promise<T> => {
      if (!flowUrl || !state.flow) throw new ApiError(410, null);
      const res = await api<T>(`${flowUrl}/${step}`, {
        body: { csrf: state.flow.csrf, ...body },
      });
      const maybe = res as unknown as Partial<PublicFlow> & { redirect_to?: string };
      if (maybe.redirect_to) {
        redirected.current = true;
        navigate(maybe.redirect_to);
      } else if (maybe.stage && maybe.csrf !== undefined && maybe.id) {
        accept(maybe as PublicFlow);
      }
      return res;
    },
    [flowUrl, state.flow, accept],
  );

  /** Refresh the state (e.g. after a CAPTCHA became required). */
  const reload = useCallback(async () => {
    if (!flowUrl) return;
    try {
      accept(await api<PublicFlow>(flowUrl));
    } catch (e) {
      setState((s) => ({ ...s, error: toFlowError(e) }));
    }
  }, [flowUrl, accept]);

  return { ...state, post, reload, redirected: redirected.current };
}
