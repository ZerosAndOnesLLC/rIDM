"use client";

import { useCallback, useEffect, useState } from "react";

import { listOrders, placeOrder, whoami, type Order, type Who } from "@/lib/api";
import { config } from "@/lib/config";
import { beginSignIn, endSessionUrl } from "@/lib/oidc";
import { getSession, signOutLocally, subscribe, type Tokens } from "@/lib/session";

/**
 * A silent sign-in that has already been tried, remembered for this tab. The
 * flag is what stops a genuinely signed-out user bouncing to rIDM and back on
 * every load.
 */
const SILENT_TRIED = "ridm.silent";

interface Loaded {
  who: Who;
  orders: Order[];
}

export default function Home() {
  const [session, setSession] = useState<Tokens | null>(getSession());
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => subscribe(setSession), []);

  /** Ask the API who this is and what it holds. No state written here. */
  const fetchAll = useCallback(
    async (): Promise<Loaded> => ({ who: await whoami(), orders: await listOrders() }),
    [],
  );

  useEffect(() => {
    if (!session) {
      // Nothing in memory — a fresh load, or a reload, since the tokens are not
      // persisted anywhere. Ask rIDM whether the browser still has an SSO
      // session, without showing the user anything.
      if (sessionStorage.getItem(SILENT_TRIED) === "1") return;
      sessionStorage.setItem(SILENT_TRIED, "1");
      void beginSignIn({ prompt: "none" }).catch((e: unknown) => setError(message(e)));
      return;
    }
    let cancelled = false;
    fetchAll().then(
      (data) => {
        if (cancelled) return;
        setLoaded(data);
        setError(null);
      },
      (e: unknown) => {
        // Reading orders needs `orders:read`; a user without it gets 403 here,
        // which is an answer rather than a failure.
        if (!cancelled) setError(message(e));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [session, fetchAll]);

  async function signIn() {
    sessionStorage.removeItem(SILENT_TRIED);
    setError(null);
    try {
      await beginSignIn();
    } catch (e) {
      setError(message(e));
    }
  }

  async function signOut() {
    const ending = await signOutLocally();
    sessionStorage.setItem(SILENT_TRIED, "1");
    if (!ending) return;
    // End the SSO session too, or the next sign-in is silent and instant and
    // the user thinks the sign-out did not work. This leaves the app for
    // rIDM's own origin, so the router is not what does it.
    window.location.assign(await endSessionUrl(ending.idToken));
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setNotice(null);
    try {
      await placeOrder(String(data.get("item") ?? ""), Number(data.get("quantity") ?? 1));
      form.reset();
      setNotice("Order placed.");
      setLoaded(await fetchAll());
    } catch (e) {
      // 403 `insufficient_scope` when the token carries no `orders:write`.
      setNotice(message(e));
    }
  }

  if (!session) {
    return (
      <>
        <h1>Orders</h1>
        <p>A single-page app that signs users in with rIDM. No client secret, no server.</p>
        {error && <p className="notice error">{error}</p>}
        <p>
          <button onClick={() => void signIn()}>Sign in</button>
        </p>
        <p className="meta">
          Issuer: <code>{config.issuer}</code>
        </p>
      </>
    );
  }

  const name =
    (session.claims.name as string | undefined) ??
    (session.claims.email as string | undefined) ??
    session.claims.sub;
  const permissions = loaded?.who.permissions ?? [];
  const orders = loaded?.orders ?? [];

  return (
    <>
      <h1>Orders</h1>
      <p>
        Signed in as <strong>{name}</strong>.
      </p>
      <p className="meta">
        Subject <code>{session.claims.sub}</code> · session{" "}
        <code>{session.claims.sid ?? "—"}</code>
        <br />
        Permissions:{" "}
        {permissions.length ? (
          permissions.map((p) => <code key={p}>{p} </code>)
        ) : (
          <em>none</em>
        )}
      </p>

      {notice && <p className="notice">{notice}</p>}
      {error && <p className="notice error">{error}</p>}

      <h2>Orders</h2>
      {orders.length === 0 ? (
        <p className="meta">No orders yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Item</th>
              <th>Qty</th>
              <th>Placed by</th>
            </tr>
          </thead>
          <tbody>
            {orders.map((order) => (
              <tr key={order.id}>
                <td>{order.item}</td>
                <td>{order.quantity}</td>
                <td>
                  <code>{order.placed_by}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {permissions.includes("orders:write") ? (
        <form onSubmit={(e) => void submit(e)}>
          <input name="item" placeholder="Item" required />
          <input
            name="quantity"
            type="number"
            defaultValue={1}
            min={1}
            style={{ width: "5rem" }}
          />
          <button type="submit">Place order</button>
        </form>
      ) : (
        <p className="meta">
          This account may read orders but not place them, so the API would answer{" "}
          <code>403 insufficient_scope</code>. Give the user the{" "}
          <code>orders-manager</code> role and sign in again.
        </p>
      )}

      <p>
        <button className="secondary" onClick={() => void signOut()}>
          Sign out
        </button>
      </p>
    </>
  );
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
