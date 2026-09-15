import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { API } from "./helpers";
import { createAdminClient } from "../lib/api/client";

/**
 * The typed admin client is generated from `api/openapi.json`; the live API
 * must serve the same document, and the client must speak to it.
 */
test.describe("OpenAPI contract", () => {
  test("live document equals the one the client was generated from", async () => {
    const res = await fetch(`${API}/openapi.json`);
    expect(res.status).toBe(200);
    const live = await res.json();
    const committed = JSON.parse(readFileSync(join(__dirname, "..", "..", "api", "openapi.json"), "utf8"));
    expect(live).toEqual(committed);
    expect(Object.keys(live.paths).length).toBeGreaterThanOrEqual(85);
  });

  test("typed client reaches the live API and types its errors", async () => {
    let unauthorized = 0;
    const client = createAdminClient({
      baseUrl: API,
      getToken: () => null,
      onUnauthorized: () => {
        unauthorized += 1;
      },
    });
    const { data, error, response } = await client.GET("/admin/me");
    expect(response.status).toBe(401);
    expect(data).toBeUndefined();
    expect(unauthorized).toBe(1);
    // The 401 body is an RFC 9457 problem, as the document declares.
    expect(error?.status).toBe(401);
    expect(typeof error?.title).toBe("string");

    const { response: forbidden } = await client.GET("/admin/permissions", {
      headers: { authorization: "Bearer not-a-token" },
    });
    expect(forbidden.status).toBe(401);
  });
});
