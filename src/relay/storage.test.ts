import { describe, it, expect } from 'vitest';
import { createMockStore } from '../test/helpers/index.js';
import { STORAGE_NAMESPACES, namespacedStore, randomId, safeEqual, sha256 } from './storage.js';

describe('storage', () => {
  describe('namespacedStore', () => {
    it('writes to the underlying store under the namespace', async () => {
      const { store, storedData } = createMockStore();
      const clients = namespacedStore<{ name: string }>(store, STORAGE_NAMESPACES.CLIENTS);

      await clients.set('abc', { name: 'x' });

      expect([...storedData.keys()]).toEqual([`${STORAGE_NAMESPACES.CLIENTS}:abc`]);
      expect(await clients.get('abc')).toEqual({ name: 'x' });
    });

    it('keeps namespaces apart', async () => {
      const { store } = createMockStore();
      const a = namespacedStore<string>(store, STORAGE_NAMESPACES.CLIENTS);
      const b = namespacedStore<string>(store, STORAGE_NAMESPACES.PENDING);

      await a.set('k', 'from-a');

      expect(await b.get('k')).toBeUndefined();
    });

    it('honours TTLs', async () => {
      const { store } = createMockStore();
      const pending = namespacedStore<string>(store, STORAGE_NAMESPACES.PENDING);

      await pending.set('k', 'v', 1);
      await new Promise((resolve) => setTimeout(resolve, 5));

      expect(await pending.get('k')).toBeUndefined();
    });

    it('works with a store that has no underlying adapter', async () => {
      const bare = { ...createMockStore().store, opts: undefined };
      const pending = namespacedStore<string>(bare, STORAGE_NAMESPACES.PENDING);

      await pending.set('k', 'v');

      expect(await pending.get('k')).toBe('v');
    });
  });

  describe('randomId', () => {
    it('returns URL-safe identifiers of the requested entropy', () => {
      expect(randomId()).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(randomId(16)).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(randomId()).not.toBe(randomId());
    });
  });

  describe('sha256', () => {
    it('hashes to base64url', () => {
      expect(sha256('abc')).toBe('ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
    });
  });

  describe('safeEqual', () => {
    it('compares strings', () => {
      expect(safeEqual('secret', 'secret')).toBe(true);
      expect(safeEqual('secret', 'secreT')).toBe(false);
      expect(safeEqual('secret', 'secret-longer')).toBe(false);
      expect(safeEqual('', '')).toBe(true);
    });
  });
});
