import { vi } from 'vitest';
import type { KeyvLike } from '../../types.js';

/**
 * Creates a mock Keyv-like store for testing.
 * Returns both the store and the underlying Map for direct data manipulation.
 */
export function createMockStore(): {
  store: KeyvLike;
  storedData: Map<string, unknown>;
} {
  const storedData = new Map<string, unknown>();

  const mockUnderlyingStore = {
    get: vi.fn((key: string) => Promise.resolve(storedData.get(key))) as KeyvLike['get'],
    set: vi.fn((key: string, value: unknown) => {
      storedData.set(key, value);
      return Promise.resolve(true);
    }),
    delete: vi.fn((key: string) => Promise.resolve(storedData.delete(key))),
    clear: vi.fn(() => Promise.resolve()),
  };

  const store: KeyvLike = {
    get: vi.fn((key: string) => Promise.resolve(storedData.get(key))) as KeyvLike['get'],
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

  return { store, storedData };
}
