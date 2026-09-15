/**
 * Typed admin API client, generated from the API's OpenAPI document.
 *
 * Regenerate the types after the API changes:
 *   (cd ../api && cargo run -p ridm-api -- openapi > openapi.json) && npm run gen:api
 *
 * `paths` and `components` come from `openapi.d.ts`; every call is checked
 * against the document, so a renamed field or route fails `npm run typecheck`.
 */
import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./openapi";

export type AdminPaths = paths;
export type Schemas = components["schemas"];

/** RFC 9457 problem document every admin error carries. */
export type Problem = Schemas["Problem"];

export interface AdminClientOptions {
  /** API origin; defaults to same-origin (the static UI is proxied or co-hosted). */
  baseUrl?: string;
  /** Returns the current admin access token, or null when signed out. */
  getToken: () => string | null | Promise<string | null>;
  /** Called on a 401 so the shell can start a fresh login. */
  onUnauthorized?: () => void;
}

export function createAdminClient(options: AdminClientOptions) {
  const client = createClient<paths>({ baseUrl: options.baseUrl ?? "" });
  const auth: Middleware = {
    async onRequest({ request }) {
      const token = await options.getToken();
      if (token) {
        request.headers.set("authorization", `Bearer ${token}`);
      }
      return request;
    },
    async onResponse({ response }) {
      if (response.status === 401) {
        options.onUnauthorized?.();
      }
      return response;
    },
  };
  client.use(auth);
  return client;
}

export type AdminClient = ReturnType<typeof createAdminClient>;
