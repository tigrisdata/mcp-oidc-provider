/**
 * Store type definitions.
 *
 * This module defines a Keyv-compatible interface that allows any version
 * of Keyv to be used without strict type conflicts.
 */

/**
 * A Keyv-compatible store interface.
 *
 * This interface matches the essential shape of a Keyv instance without
 * requiring the exact Keyv type. This allows users to pass any Keyv instance
 * regardless of the exact version installed.
 *
 * @example
 * ```typescript
 * import { Keyv } from 'keyv';
 * import { KeyvTigris } from 'keyv-tigris';
 *
 * // All of these work:
 * const inMemory = new Keyv();
 * const withTigris = new Keyv({ store: new KeyvTigris() });
 * ```
 */
export interface KeyvLike {
  /**
   * Get a value by key.
   */
  get<T = unknown>(key: string): Promise<T | undefined>;

  /**
   * Set a value with optional TTL in milliseconds.
   */
  set<T = unknown>(key: string, value: T, ttl?: number): Promise<boolean>;

  /**
   * Delete a key.
   */
  delete(key: string): Promise<boolean>;

  /**
   * Clear all keys in this namespace.
   */
  clear(): Promise<void>;

  /**
   * Options containing the underlying store.
   * Used internally to create namespaced instances.
   */
  opts?: {
    store?: unknown;
    [key: string]: unknown;
  };
}
