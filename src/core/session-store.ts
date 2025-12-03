import type { KeyValueStore } from '../types/storage.js';
import type { UserSession, SessionStore } from '../types/session.js';
import { DEFAULT_USER_SESSION_TTL_MS } from './config.js';

/**
 * Create a session store using a Keyv-compatible storage backend.
 *
 * @param store - The underlying key-value store
 * @param defaultTtl - Default TTL in milliseconds (default: 30 days)
 * @returns SessionStore implementation
 */
export function createSessionStore(
  store: KeyValueStore<UserSession>,
  defaultTtl: number = DEFAULT_USER_SESSION_TTL_MS
): SessionStore {
  return {
    async set(sessionId: string, session: UserSession, ttl?: number): Promise<void> {
      await store.set(sessionId, session, ttl ?? defaultTtl);
    },

    async get(sessionId: string): Promise<UserSession | undefined> {
      return store.get(sessionId);
    },

    async delete(sessionId: string): Promise<boolean> {
      return store.delete(sessionId);
    },

    async clear(): Promise<void> {
      await store.clear();
    },
  };
}

/**
 * Extended session store with additional helper methods.
 */
export interface ExtendedSessionStore extends SessionStore {
  /**
   * Update the token set for a user session.
   * @param sessionId - The session ID
   * @param tokenSet - The new token set
   * @returns true if successful, false if session not found
   */
  updateTokenSet(sessionId: string, tokenSet: UserSession['tokenSet']): Promise<boolean>;

  /**
   * Update custom data for a user session.
   * @param sessionId - The session ID
   * @param customData - The custom data to set
   * @returns true if successful, false if session not found
   */
  updateCustomData(sessionId: string, customData: Record<string, unknown>): Promise<boolean>;
}

/**
 * Create an extended session store with additional helper methods.
 *
 * @param store - The underlying key-value store
 * @param defaultTtl - Default TTL in milliseconds (default: 30 days)
 * @returns ExtendedSessionStore implementation
 */
export function createExtendedSessionStore(
  store: KeyValueStore<UserSession>,
  defaultTtl: number = DEFAULT_USER_SESSION_TTL_MS
): ExtendedSessionStore {
  const baseStore = createSessionStore(store, defaultTtl);

  return {
    ...baseStore,

    async updateTokenSet(sessionId: string, tokenSet: UserSession['tokenSet']): Promise<boolean> {
      const session = await store.get(sessionId);
      if (!session) {
        return false;
      }

      session.tokenSet = tokenSet;
      await store.set(sessionId, session, defaultTtl);
      return true;
    },

    async updateCustomData(
      sessionId: string,
      customData: Record<string, unknown>
    ): Promise<boolean> {
      const session = await store.get(sessionId);
      if (!session) {
        return false;
      }

      session.customData = customData;
      await store.set(sessionId, session, defaultTtl);
      return true;
    },
  };
}
