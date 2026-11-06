/**
 * Storage helpers: namespaced Keyv views over the caller's store, random
 * identifiers and hashing.
 * @internal
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { Keyv } from 'keyv';
import type { KeyvLike } from '../types.js';

/** Keyv namespaces used by the relay. */
export const STORAGE_NAMESPACES = {
  /** Dynamically registered clients, keyed by `client_id`. */
  CLIENTS: 'mcp-relay:clients',
  /** In-flight authorization requests (consent, upstream state, relay codes). */
  PENDING: 'mcp-relay:pending',
  /** Cached Client ID Metadata Documents, keyed by the `client_id` URL. */
  CIMD: 'mcp-relay:cimd',
} as const;

/**
 * Create a Keyv instance that shares the caller's underlying store but writes
 * under its own namespace. A store without an underlying adapter (plain
 * in-memory Keyv) gets its own in-memory map, which is fine for a single
 * process.
 */
export function namespacedStore<T>(store: KeyvLike, namespace: string): Keyv<T> {
  const underlying = store.opts?.store;
  return new Keyv<T>(underlying ? { store: underlying as never, namespace } : { namespace });
}

/** URL-safe random identifier with `bytes` bytes of entropy (default 32). */
export function randomId(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** SHA-256 of a UTF-8 string, base64url encoded. */
export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

/** Constant-time comparison of two strings. */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
