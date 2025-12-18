import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOidcAdapterFactory } from './oidc-adapter.js';
import { noopLogger } from '../utils/logger.js';
import type { KeyvLike } from '../types.js';

describe('oidc-adapter', () => {
  let mockStore: KeyvLike;
  let storedData: Map<string, unknown>;

  beforeEach(() => {
    storedData = new Map();
    const mockUnderlyingStore = {
      get: vi.fn((key: string) => Promise.resolve(storedData.get(key))),
      set: vi.fn((key: string, value: unknown) => {
        storedData.set(key, value);
        return Promise.resolve(true);
      }),
      delete: vi.fn((key: string) => {
        const existed = storedData.has(key);
        storedData.delete(key);
        return Promise.resolve(existed);
      }),
      clear: vi.fn(() => {
        storedData.clear();
        return Promise.resolve();
      }),
    };

    mockStore = {
      get: vi.fn((key: string) => Promise.resolve(storedData.get(key))),
      set: vi.fn((key: string, value: unknown) => {
        storedData.set(key, value);
        return Promise.resolve(true);
      }),
      delete: vi.fn((key: string) => Promise.resolve(storedData.delete(key))),
      clear: vi.fn(() => Promise.resolve()),
      opts: {
        store: mockUnderlyingStore,
      },
    };
  });

  describe('createOidcAdapterFactory', () => {
    it('should create an adapter factory', () => {
      const factory = createOidcAdapterFactory(mockStore, noopLogger);

      expect(factory).toBeDefined();
      expect(typeof factory).toBe('function');
    });

    it('should create adapters for different model names', () => {
      const factory = createOidcAdapterFactory(mockStore, noopLogger);

      const accessTokenAdapter = factory('AccessToken');
      const sessionAdapter = factory('Session');

      expect(accessTokenAdapter).toBeDefined();
      expect(sessionAdapter).toBeDefined();
    });
  });

  describe('KeyvOidcAdapter', () => {
    let adapter: ReturnType<ReturnType<typeof createOidcAdapterFactory>>;

    beforeEach(() => {
      const factory = createOidcAdapterFactory(mockStore, noopLogger);
      adapter = factory('TestModel');
    });

    describe('upsert and find', () => {
      it('should store and retrieve a payload', async () => {
        const payload = { sub: 'user-123', kind: 'test' };

        await adapter.upsert('test-id', payload, 3600);
        const result = await adapter.find('test-id');

        expect(result).toEqual(payload);
      });

      it('should return undefined for non-existent payload', async () => {
        const result = await adapter.find('non-existent');

        expect(result).toBeUndefined();
      });

      it('should handle payload with uid', async () => {
        const payload = { sub: 'user-123', uid: 'unique-id' };

        await adapter.upsert('test-id', payload, 3600);

        // Should be findable by id
        const byId = await adapter.find('test-id');
        expect(byId).toEqual(payload);

        // Should be findable by uid
        const byUid = await adapter.findByUid('unique-id');
        expect(byUid).toEqual(payload);
      });

      it('should handle payload with grantId', async () => {
        const payload = { sub: 'user-123', grantId: 'grant-123' };

        await adapter.upsert('test-id', payload, 3600);

        const result = await adapter.find('test-id');
        expect(result).toEqual(payload);
      });
    });

    describe('findByUid', () => {
      it('should find a payload by uid', async () => {
        const payload = { sub: 'user-123', uid: 'unique-id' };
        await adapter.upsert('test-id', payload, 3600);

        const result = await adapter.findByUid('unique-id');

        expect(result).toEqual(payload);
      });

      it('should return undefined for non-existent uid', async () => {
        const result = await adapter.findByUid('non-existent');

        expect(result).toBeUndefined();
      });
    });

    describe('findByUserCode', () => {
      it('should return undefined (device flow not supported)', async () => {
        const result = await adapter.findByUserCode('user-code');

        expect(result).toBeUndefined();
      });
    });

    describe('consume', () => {
      it('should mark a payload as consumed', async () => {
        const payload = { sub: 'user-123' };
        await adapter.upsert('test-id', payload, 3600);

        await adapter.consume('test-id');

        const consumed = await adapter.find('test-id');
        expect(consumed?.consumed).toBeDefined();
        expect(typeof consumed?.consumed).toBe('number');
      });

      it('should update uid-indexed copy when consuming', async () => {
        const payload = { sub: 'user-123', uid: 'unique-id' };
        await adapter.upsert('test-id', payload, 3600);

        await adapter.consume('test-id');

        const consumedByUid = await adapter.findByUid('unique-id');
        expect(consumedByUid?.consumed).toBeDefined();
      });

      it('should do nothing for non-existent payload', async () => {
        // Should not throw
        await adapter.consume('non-existent');
      });
    });

    describe('destroy', () => {
      it('should delete a payload', async () => {
        const payload = { sub: 'user-123' };
        await adapter.upsert('test-id', payload, 3600);

        await adapter.destroy('test-id');

        const result = await adapter.find('test-id');
        expect(result).toBeUndefined();
      });

      it('should delete uid-indexed copy', async () => {
        const payload = { sub: 'user-123', uid: 'unique-id' };
        await adapter.upsert('test-id', payload, 3600);

        await adapter.destroy('test-id');

        const byId = await adapter.find('test-id');
        const byUid = await adapter.findByUid('unique-id');
        expect(byId).toBeUndefined();
        expect(byUid).toBeUndefined();
      });

      it('should handle non-existent payload', async () => {
        // Should not throw
        await adapter.destroy('non-existent');
      });
    });

    describe('revokeByGrantId', () => {
      it('should delete all payloads associated with a grant', async () => {
        const payload1 = { sub: 'user-123', grantId: 'grant-123' };
        const payload2 = { sub: 'user-456', grantId: 'grant-123' };

        await adapter.upsert('id-1', payload1, 3600);
        await adapter.upsert('id-2', payload2, 3600);

        await adapter.revokeByGrantId('grant-123');

        const result1 = await adapter.find('id-1');
        const result2 = await adapter.find('id-2');
        expect(result1).toBeUndefined();
        expect(result2).toBeUndefined();
      });

      it('should handle non-existent grantId', async () => {
        // Should not throw
        await adapter.revokeByGrantId('non-existent');
      });
    });

    describe('multiple adapters', () => {
      it('should isolate data between different model adapters', async () => {
        const factory = createOidcAdapterFactory(mockStore, noopLogger);
        const adapter1 = factory('Model1');
        const adapter2 = factory('Model2');

        const payload1 = { sub: 'user-1', model: '1' };
        const payload2 = { sub: 'user-2', model: '2' };

        await adapter1.upsert('id-1', payload1, 3600);
        await adapter2.upsert('id-1', payload2, 3600);

        const result1 = await adapter1.find('id-1');
        const result2 = await adapter2.find('id-1');

        expect(result1).toEqual(payload1);
        expect(result2).toEqual(payload2);
      });
    });
  });
});
