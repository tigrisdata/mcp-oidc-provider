import type { Adapter, AdapterPayload } from 'oidc-provider';
import { Keyv } from 'keyv';
import type { KeyvLike } from '../types.js';
import type { Logger } from '../utils/logger.js';

/**
 * Factory function for creating OIDC adapters.
 */
export type OidcAdapterFactory = (name: string) => Adapter;

/**
 * Create a factory function for OIDC adapters using a Keyv store.
 *
 * @param store - Keyv instance (underlying store is extracted for namespacing)
 * @param logger - Logger instance
 * @returns Adapter factory function for oidc-provider
 */
export function createOidcAdapterFactory(store: KeyvLike, logger: Logger): OidcAdapterFactory {
  // Get the underlying store to create namespaced Keyv instances
  const underlyingStore = store.opts?.store;

  return (name: string) => new KeyvOidcAdapter(name, underlyingStore, logger);
}

/**
 * Keyv-based adapter for oidc-provider.
 * Stores OAuth tokens, grants, sessions, etc.
 */
class KeyvOidcAdapter implements Adapter {
  private name: string;
  private store: Keyv<AdapterPayload>;
  private grantIdStore: Keyv<string[]>;
  private logger: Logger;

  constructor(name: string, underlyingStore: unknown, logger: Logger) {
    this.name = name;
    this.logger = logger;

    // Create namespaced Keyv instances
    this.store = new Keyv<AdapterPayload>({
      store: underlyingStore as Keyv['opts']['store'],
      namespace: `oidc:${name}`,
    });
    this.grantIdStore = new Keyv<string[]>({
      store: underlyingStore as Keyv['opts']['store'],
      namespace: `oidc:${name}:grantId`,
    });
  }

  /**
   * Insert or update a record.
   */
  async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    const key = this.key(id);
    const ttl = expiresIn * 1000; // Convert to milliseconds

    // Store the payload with TTL
    await this.store.set(key, payload, ttl);

    // For Interaction model, also store by UID for findByUid lookup
    const { uid } = payload;
    if (uid) {
      const uidKey = this.uidKey(uid);
      await this.store.set(uidKey, payload, ttl);
    }

    // If this payload has a grantId, maintain the index
    if (payload.grantId) {
      await this.addToGrantIndex(payload.grantId, id);
    }

    this.logger.debug('OIDC adapter upsert', { name: this.name, id, uid, expiresIn });
  }

  /**
   * Find a record by ID.
   */
  async find(id: string): Promise<AdapterPayload | undefined> {
    const key = this.key(id);
    const payload = await this.store.get(key);

    this.logger.debug('OIDC adapter find', { name: this.name, id, found: !!payload });
    return payload;
  }

  /**
   * Find by user code (for device flow).
   */
  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    // Device flow not supported, but interface requires this method
    this.logger.debug('OIDC adapter findByUserCode', { name: this.name, userCode });
    return undefined;
  }

  /**
   * Find by UID (for interactions).
   */
  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const key = this.uidKey(uid);
    const payload = await this.store.get(key);

    this.logger.debug('OIDC adapter findByUid', { name: this.name, uid, found: !!payload });
    return payload;
  }

  /**
   * Mark a record as consumed (for one-time use tokens).
   */
  async consume(id: string): Promise<void> {
    const payload = await this.find(id);
    if (payload) {
      payload.consumed = Math.floor(Date.now() / 1000);
      await this.store.set(this.key(id), payload);

      // Also update the UID-indexed copy if it exists
      const { uid } = payload;
      if (uid) {
        await this.store.set(this.uidKey(uid), payload);
      }

      this.logger.debug('OIDC adapter consume', { name: this.name, id });
    }
  }

  /**
   * Destroy a record.
   */
  async destroy(id: string): Promise<void> {
    // Get the payload first to check if we need to clean up UID index
    const payload = await this.find(id);

    // Delete the main record
    const key = this.key(id);
    await this.store.delete(key);

    // If this had a UID, also delete the UID-indexed copy
    if (payload) {
      const { uid } = payload;
      if (uid) {
        const uidKey = this.uidKey(uid);
        await this.store.delete(uidKey);
      }
    }

    this.logger.debug('OIDC adapter destroy', { name: this.name, id });
  }

  /**
   * Revoke all records associated with a grantId.
   */
  async revokeByGrantId(grantId: string): Promise<void> {
    const grantKey = this.grantKey(grantId);
    const ids = await this.grantIdStore.get(grantKey);

    if (ids && ids.length > 0) {
      // Delete all records associated with this grant
      await Promise.all(ids.map((id) => this.destroy(id)));

      // Clear the grant index
      await this.grantIdStore.delete(grantKey);

      this.logger.debug('OIDC adapter revokeByGrantId', {
        name: this.name,
        grantId,
        count: ids.length,
      });
    }
  }

  /**
   * Add an ID to the grantId index.
   */
  private async addToGrantIndex(grantId: string, id: string): Promise<void> {
    const grantKey = this.grantKey(grantId);
    const ids = (await this.grantIdStore.get(grantKey)) ?? [];

    if (!ids.includes(id)) {
      ids.push(id);
      await this.grantIdStore.set(grantKey, ids);
    }
  }

  /**
   * Generate storage key for an ID.
   */
  private key(id: string): string {
    return `${this.name}:${id}`;
  }

  /**
   * Generate storage key for a UID.
   */
  private uidKey(uid: string): string {
    return `${this.name}:uid:${uid}`;
  }

  /**
   * Generate storage key for a grantId.
   */
  private grantKey(grantId: string): string {
    return `grant:${grantId}`;
  }
}
