import { Store, SessionData } from 'express-session';
import type { KeyValueStore } from '../types.js';

/**
 * Express session store adapter for Keyv-compatible stores.
 * Allows using any Keyv backend (Redis, Tigris, etc.) as Express session storage.
 *
 * @internal This is an internal utility used by setupMcpExpress and createOidcServer.
 *
 * @example
 * ```typescript
 * import session from 'express-session';
 * import Keyv from 'keyv';
 *
 * const keyv = new Keyv('redis://localhost:6379');
 * const store = new KeyvSessionStore(keyv);
 *
 * app.use(session({
 *   store,
 *   secret: 'your-secret',
 *   resave: false,
 *   saveUninitialized: false,
 * }));
 * ```
 */
export class KeyvSessionStore extends Store {
  private store: KeyValueStore<SessionData>;

  constructor(store: KeyValueStore<SessionData>) {
    super();
    this.store = store;
  }

  /**
   * Get a session by session ID.
   */
  override get(
    sid: string,
    callback: (err?: Error | null, session?: SessionData | null) => void
  ): void {
    this.store
      .get(sid)
      .then((session) => {
        callback(null, session ?? null);
      })
      .catch((err: unknown) => {
        callback(err as Error);
      });
  }

  /**
   * Set/update a session.
   */
  override set(sid: string, session: SessionData, callback?: (err?: Error) => void): void {
    // Calculate TTL from session cookie maxAge if available
    const ttl = session.cookie.maxAge ?? undefined;

    this.store
      .set(sid, session, ttl)
      .then(() => {
        callback?.();
      })
      .catch((err: unknown) => {
        callback?.(err as Error);
      });
  }

  /**
   * Destroy a session.
   */
  override destroy(sid: string, callback?: (err?: Error) => void): void {
    this.store
      .delete(sid)
      .then(() => {
        callback?.();
      })
      .catch((err: unknown) => {
        callback?.(err as Error);
      });
  }

  /**
   * Touch a session to reset its TTL.
   */
  override touch(sid: string, session: SessionData, callback?: (err?: Error) => void): void {
    // Update TTL by re-setting the session
    this.set(sid, session, callback);
  }
}
