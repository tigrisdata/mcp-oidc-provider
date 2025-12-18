import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KeyvSessionStore } from './session-store.js';
import type { SessionData } from 'express-session';
import type { KeyValueStore } from '../types.js';

describe('KeyvSessionStore', () => {
  let mockStore: KeyValueStore<SessionData>;
  let storedData: Map<string, SessionData>;
  let sessionStore: KeyvSessionStore;

  const createMockSession = (overrides?: Partial<SessionData>): SessionData => ({
    cookie: {
      originalMaxAge: 86400000,
      maxAge: 86400000,
    },
    ...overrides,
  });

  beforeEach(() => {
    storedData = new Map();
    mockStore = {
      get: vi.fn((key: string) => Promise.resolve(storedData.get(key))),
      set: vi.fn((key: string, value: SessionData, _ttl?: number) => {
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
    sessionStore = new KeyvSessionStore(mockStore);
  });

  describe('get', () => {
    it('should retrieve a session', async () => {
      const session = createMockSession();
      storedData.set('session-1', session);

      const result = await new Promise<SessionData | null | undefined>((resolve, reject) => {
        sessionStore.get('session-1', (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });

      expect(result).toEqual(session);
      expect(mockStore.get).toHaveBeenCalledWith('session-1');
    });

    it('should return null for non-existent session', async () => {
      const result = await new Promise<SessionData | null | undefined>((resolve, reject) => {
        sessionStore.get('non-existent', (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });

      expect(result).toBeNull();
    });

    it('should pass error to callback on failure', async () => {
      const error = new Error('Store error');
      vi.mocked(mockStore.get).mockRejectedValueOnce(error);

      await expect(
        new Promise<SessionData | null | undefined>((resolve, reject) => {
          sessionStore.get('session-1', (err, result) => {
            if (err) reject(err);
            else resolve(result);
          });
        })
      ).rejects.toThrow('Store error');
    });
  });

  describe('set', () => {
    it('should store a session', async () => {
      const session = createMockSession();

      await new Promise<void>((resolve, reject) => {
        sessionStore.set('session-1', session, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      expect(mockStore.set).toHaveBeenCalledWith('session-1', session, 86400000);
    });

    it('should use maxAge from cookie as TTL', async () => {
      const session = createMockSession({
        cookie: { originalMaxAge: 3600000, maxAge: 3600000 },
      });

      await new Promise<void>((resolve, reject) => {
        sessionStore.set('session-1', session, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      expect(mockStore.set).toHaveBeenCalledWith('session-1', session, 3600000);
    });

    it('should handle undefined maxAge', async () => {
      const session = createMockSession({
        cookie: { originalMaxAge: null },
      });
      // Remove maxAge
      delete (session.cookie as { maxAge?: number }).maxAge;

      await new Promise<void>((resolve, reject) => {
        sessionStore.set('session-1', session, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      expect(mockStore.set).toHaveBeenCalledWith('session-1', session, undefined);
    });

    it('should work without callback', () => {
      const session = createMockSession();

      // Should not throw
      sessionStore.set('session-1', session);

      expect(mockStore.set).toHaveBeenCalled();
    });

    it('should pass error to callback on failure', async () => {
      const error = new Error('Store error');
      vi.mocked(mockStore.set).mockRejectedValueOnce(error);
      const session = createMockSession();

      await expect(
        new Promise<void>((resolve, reject) => {
          sessionStore.set('session-1', session, (err) => {
            if (err) reject(err);
            else resolve();
          });
        })
      ).rejects.toThrow('Store error');
    });
  });

  describe('destroy', () => {
    it('should delete a session', async () => {
      storedData.set('session-1', createMockSession());

      await new Promise<void>((resolve, reject) => {
        sessionStore.destroy('session-1', (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      expect(mockStore.delete).toHaveBeenCalledWith('session-1');
    });

    it('should work without callback', () => {
      storedData.set('session-1', createMockSession());

      // Should not throw
      sessionStore.destroy('session-1');

      expect(mockStore.delete).toHaveBeenCalled();
    });

    it('should pass error to callback on failure', async () => {
      const error = new Error('Store error');
      vi.mocked(mockStore.delete).mockRejectedValueOnce(error);

      await expect(
        new Promise<void>((resolve, reject) => {
          sessionStore.destroy('session-1', (err) => {
            if (err) reject(err);
            else resolve();
          });
        })
      ).rejects.toThrow('Store error');
    });
  });

  describe('touch', () => {
    it('should update TTL by re-setting the session', async () => {
      const session = createMockSession();
      storedData.set('session-1', session);

      await new Promise<void>((resolve, reject) => {
        sessionStore.touch('session-1', session, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      expect(mockStore.set).toHaveBeenCalledWith('session-1', session, 86400000);
    });

    it('should work without callback', () => {
      const session = createMockSession();

      // Should not throw
      sessionStore.touch('session-1', session);

      expect(mockStore.set).toHaveBeenCalled();
    });
  });
});
