import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createSessionStore, createExtendedSessionStore } from './session-store.js';
import type { KeyValueStore, UserSession } from '../types.js';

describe('session-store', () => {
  let mockStore: KeyValueStore<UserSession>;
  let storedData: Map<string, UserSession>;

  const createMockSession = (overrides?: Partial<UserSession>): UserSession => ({
    userId: 'user-123',
    claims: { sub: 'user-123', email: 'test@example.com' },
    tokenSet: {
      accessToken: 'access-token',
      idToken: 'id-token',
      refreshToken: 'refresh-token',
      expiresAt: Date.now() + 3600000,
    },
    ...overrides,
  });

  beforeEach(() => {
    storedData = new Map();
    mockStore = {
      get: vi.fn((key: string) => Promise.resolve(storedData.get(key))),
      set: vi.fn((key: string, value: UserSession, _ttl?: number) => {
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
  });

  describe('createSessionStore', () => {
    it('should create a session store', () => {
      const store = createSessionStore(mockStore);

      expect(store.get).toBeDefined();
      expect(store.set).toBeDefined();
      expect(store.delete).toBeDefined();
      expect(store.clear).toBeDefined();
    });

    it('should set a session with default TTL', async () => {
      const store = createSessionStore(mockStore);
      const session = createMockSession();

      await store.set('session-1', session);

      expect(mockStore.set).toHaveBeenCalledWith(
        'session-1',
        session,
        30 * 24 * 60 * 60 * 1000 // DEFAULT_USER_SESSION_TTL_MS
      );
    });

    it('should set a session with custom TTL', async () => {
      const store = createSessionStore(mockStore);
      const session = createMockSession();

      await store.set('session-1', session, 60000);

      expect(mockStore.set).toHaveBeenCalledWith('session-1', session, 60000);
    });

    it('should set a session with custom default TTL', async () => {
      const customTtl = 7200000;
      const store = createSessionStore(mockStore, customTtl);
      const session = createMockSession();

      await store.set('session-1', session);

      expect(mockStore.set).toHaveBeenCalledWith('session-1', session, customTtl);
    });

    it('should get a session', async () => {
      const store = createSessionStore(mockStore);
      const session = createMockSession();
      storedData.set('session-1', session);

      const result = await store.get('session-1');

      expect(result).toEqual(session);
      expect(mockStore.get).toHaveBeenCalledWith('session-1');
    });

    it('should return undefined for non-existent session', async () => {
      const store = createSessionStore(mockStore);

      const result = await store.get('non-existent');

      expect(result).toBeUndefined();
    });

    it('should delete a session', async () => {
      const store = createSessionStore(mockStore);
      storedData.set('session-1', createMockSession());

      const result = await store.delete('session-1');

      expect(result).toBe(true);
      expect(mockStore.delete).toHaveBeenCalledWith('session-1');
    });

    it('should return false when deleting non-existent session', async () => {
      const store = createSessionStore(mockStore);

      const result = await store.delete('non-existent');

      expect(result).toBe(false);
    });

    it('should clear all sessions', async () => {
      const store = createSessionStore(mockStore);
      storedData.set('session-1', createMockSession());
      storedData.set('session-2', createMockSession());

      await store.clear();

      expect(mockStore.clear).toHaveBeenCalled();
    });
  });

  describe('createExtendedSessionStore', () => {
    it('should create an extended session store with all base methods', () => {
      const store = createExtendedSessionStore(mockStore);

      expect(store.get).toBeDefined();
      expect(store.set).toBeDefined();
      expect(store.delete).toBeDefined();
      expect(store.clear).toBeDefined();
      expect(store.updateTokenSet).toBeDefined();
      expect(store.updateCustomData).toBeDefined();
    });

    it('should update token set for existing session', async () => {
      const store = createExtendedSessionStore(mockStore);
      const session = createMockSession();
      storedData.set('session-1', session);

      const newTokenSet = {
        accessToken: 'new-access-token',
        idToken: 'new-id-token',
        refreshToken: 'new-refresh-token',
        expiresAt: Date.now() + 7200000,
      };

      const result = await store.updateTokenSet('session-1', newTokenSet);

      expect(result).toBe(true);
      const updatedSession = storedData.get('session-1');
      expect(updatedSession?.tokenSet).toEqual(newTokenSet);
    });

    it('should return false when updating token set for non-existent session', async () => {
      const store = createExtendedSessionStore(mockStore);

      const result = await store.updateTokenSet('non-existent', {
        accessToken: 'token',
        idToken: 'id',
        refreshToken: 'refresh',
      });

      expect(result).toBe(false);
    });

    it('should update custom data for existing session', async () => {
      const store = createExtendedSessionStore(mockStore);
      const session = createMockSession();
      storedData.set('session-1', session);

      const customData = { organization: 'org-1', role: 'admin' };

      const result = await store.updateCustomData('session-1', customData);

      expect(result).toBe(true);
      const updatedSession = storedData.get('session-1');
      expect(updatedSession?.customData).toEqual(customData);
    });

    it('should return false when updating custom data for non-existent session', async () => {
      const store = createExtendedSessionStore(mockStore);

      const result = await store.updateCustomData('non-existent', { foo: 'bar' });

      expect(result).toBe(false);
    });

    it('should use default TTL when updating token set', async () => {
      const customTtl = 7200000;
      const store = createExtendedSessionStore(mockStore, customTtl);
      const session = createMockSession();
      storedData.set('session-1', session);

      await store.updateTokenSet('session-1', {
        accessToken: 'new',
        idToken: 'new',
        refreshToken: 'new',
      });

      // Check that the last call to set used the custom TTL
      const setCalls = vi.mocked(mockStore.set).mock.calls;
      const lastCall = setCalls[setCalls.length - 1];
      expect(lastCall[2]).toBe(customTtl);
    });

    it('should use default TTL when updating custom data', async () => {
      const customTtl = 7200000;
      const store = createExtendedSessionStore(mockStore, customTtl);
      const session = createMockSession();
      storedData.set('session-1', session);

      await store.updateCustomData('session-1', { foo: 'bar' });

      const setCalls = vi.mocked(mockStore.set).mock.calls;
      const lastCall = setCalls[setCalls.length - 1];
      expect(lastCall[2]).toBe(customTtl);
    });

    it('should preserve other session fields when updating token set', async () => {
      const store = createExtendedSessionStore(mockStore);
      const session = createMockSession({
        customData: { existing: 'data' },
      });
      storedData.set('session-1', session);

      await store.updateTokenSet('session-1', {
        accessToken: 'new',
        idToken: 'new',
        refreshToken: 'new',
      });

      const updatedSession = storedData.get('session-1');
      expect(updatedSession?.userId).toBe('user-123');
      expect(updatedSession?.customData).toEqual({ existing: 'data' });
    });

    it('should preserve other session fields when updating custom data', async () => {
      const store = createExtendedSessionStore(mockStore);
      const session = createMockSession();
      storedData.set('session-1', session);

      await store.updateCustomData('session-1', { new: 'data' });

      const updatedSession = storedData.get('session-1');
      expect(updatedSession?.userId).toBe('user-123');
      expect(updatedSession?.tokenSet.accessToken).toBe('access-token');
    });
  });
});
