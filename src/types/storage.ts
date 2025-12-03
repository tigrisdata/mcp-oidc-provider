/**
 * Generic key-value storage interface.
 * Compatible with Keyv API for easy integration.
 *
 * @example
 * ```typescript
 * // Using with Keyv
 * import Keyv from 'keyv';
 *
 * const keyv = new Keyv('redis://localhost:6379');
 * const store: KeyValueStore<MyData> = {
 *   get: (key) => keyv.get(key),
 *   set: (key, value, ttl) => keyv.set(key, value, ttl),
 *   delete: (key) => keyv.delete(key),
 *   clear: () => keyv.clear(),
 * };
 * ```
 */
export interface KeyValueStore<T = unknown> {
  /**
   * Get a value by key.
   * @param key - The key to look up
   * @returns The value, or undefined if not found
   */
  get(key: string): Promise<T | undefined>;

  /**
   * Set a value with optional TTL.
   * @param key - The key to set
   * @param value - The value to store
   * @param ttl - Optional TTL in milliseconds
   * @returns true if successful
   */
  set(key: string, value: T, ttl?: number): Promise<boolean>;

  /**
   * Delete a value by key.
   * @param key - The key to delete
   * @returns true if the key existed and was deleted
   */
  delete(key: string): Promise<boolean>;

  /**
   * Clear all values in this store/namespace.
   */
  clear(): Promise<void>;

  /**
   * Check if a key exists.
   * @param key - The key to check
   * @returns true if the key exists
   */
  has?(key: string): Promise<boolean>;
}

/**
 * Factory function for creating namespaced key-value stores.
 * This allows creating separate stores for different data types.
 *
 * @example
 * ```typescript
 * import Keyv from 'keyv';
 *
 * const createStore: StoreFactory = (namespace, ttl) => {
 *   const keyv = new Keyv({
 *     namespace,
 *     ttl,
 *     store: new KeyvRedis('redis://localhost:6379'),
 *   });
 *   return keyv;
 * };
 * ```
 */
export type StoreFactory = <T>(namespace: string, ttl?: number) => KeyValueStore<T>;
