import type { AuthApi, StoredSession } from "@/lib/console/auth";
import { isExpiring } from "@/lib/console/auth";

export type SessionStatus = "loading" | "signed_out" | "signed_in";

export interface Snapshot<Me> {
  status: SessionStatus;
  session: StoredSession | null;
  /** Who is signed in, once the "me" call answered. */
  me: Me | null;
  /** Why the last session ended, shown on the sign-in card. */
  notice: string | null;
}

/**
 * A console's session, outside React: the API client's token getter runs
 * inside fetches, a refresh must be shared by every request that needs one,
 * and components read it through `useSyncExternalStore` so a page that
 * hydrates after the session was restored still matches its server HTML.
 * One instance per console (admin, account), each with its own auth bundle.
 */
export class SessionStore<Me> {
  private readonly loading: Snapshot<Me> = { status: "loading", session: null, me: null, notice: null };
  private session: StoredSession | null = null;
  private me: Me | null = null;
  private notice: string | null = null;
  private restored = false;
  private snap: Snapshot<Me> = this.loading;
  private refreshing: Promise<StoredSession> | null = null;
  private listeners = new Set<() => void>();

  constructor(private readonly auth: AuthApi) {}

  subscribe = (cb: () => void): (() => void) => {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  };

  snapshot = (): Snapshot<Me> => this.snap;
  serverSnapshot = (): Snapshot<Me> => this.loading;

  private emit() {
    const status: SessionStatus = !this.restored ? "loading" : !this.session ? "signed_out" : this.me ? "signed_in" : "loading";
    this.snap = { status, session: this.session, me: this.session ? this.me : null, notice: this.notice };
    this.listeners.forEach((l) => l());
  }

  current(): StoredSession | null {
    return this.session;
  }

  set(session: StoredSession) {
    this.session = session;
    this.emit();
  }

  identify(me: Me) {
    this.me = me;
    this.emit();
  }

  markRestored() {
    this.restored = true;
    this.emit();
  }

  end(why: string | null) {
    this.session = null;
    this.me = null;
    this.notice = why;
    this.auth.clearSession();
    this.emit();
  }

  /** A valid access token, refreshing (once, shared) when it is about to expire. */
  async token(): Promise<string | null> {
    const s = this.session;
    if (!s) return null;
    if (!isExpiring(s) || !s.refresh_token) return s.access_token;
    this.refreshing ??= this.auth.refreshSession(s).finally(() => {
      this.refreshing = null;
    });
    try {
      const next = await this.refreshing;
      this.set(next);
      return next.access_token;
    } catch {
      this.end("Your session has expired. Sign in again.");
      return null;
    }
  }

  /** A 401 despite a fresh-looking token: refresh once, otherwise the session is gone. */
  unauthorized() {
    const s = this.session;
    if (!s) return;
    this.session = { ...s, expires_at: 0 };
    void this.token();
  }
}
