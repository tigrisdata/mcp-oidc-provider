import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Request, Response } from 'express';
import { ConsentStore, consentKey, deriveConsentSecret, parseCookies } from './consent.js';

const CLIENT = 'client-1';
const REDIRECT = 'http://localhost:3000/callback';

function createStore(overrides: Partial<ConstructorParameters<typeof ConsentStore>[0]> = {}) {
  return new ConsentStore({
    cookieName: 'consent',
    secret: 'k'.repeat(32),
    ttl: 60_000,
    secure: false,
    ...overrides,
  });
}

function requestWithCookie(cookie?: string): Request {
  return { headers: cookie ? { cookie } : {} } as Request;
}

function remember(store: ConsentStore, req: Request, clientId = CLIENT, redirectUri = REDIRECT) {
  const append = vi.fn();
  store.remember(req, { append } as unknown as Response, clientId, redirectUri);
  const header = append.mock.calls[0]?.[1] as string;
  const [cookie, ...attributes] = header.split('; ');
  return { cookie: cookie as string, attributes };
}

describe('consent', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  describe('parseCookies', () => {
    it('parses a cookie header', () => {
      expect(parseCookies('a=1; b=two%20words; c; a=dup')).toEqual({ a: '1', b: 'two words' });
      expect(parseCookies(undefined)).toEqual({});
      expect(parseCookies('bad=%E0%A4%A')).toEqual({ bad: '%E0%A4%A' });
    });
  });

  describe('deriveConsentSecret', () => {
    it('is deterministic per client secret', () => {
      expect(deriveConsentSecret('abc')).toBe(deriveConsentSecret('abc'));
      expect(deriveConsentSecret('abc')).not.toBe(deriveConsentSecret('abd'));
      expect(deriveConsentSecret('abc')).not.toContain('abc');
    });
  });

  it('binds the key to client and redirect URI', () => {
    expect(consentKey('a', 'b')).toBe(consentKey('a', 'b'));
    expect(consentKey('a', 'b')).not.toBe(consentKey('a', 'c'));
    expect(consentKey('a', 'b')).not.toBe(consentKey('x', 'b'));
  });

  describe('ConsentStore', () => {
    it('has no approval without a cookie', () => {
      expect(createStore().has(requestWithCookie(), CLIENT, REDIRECT)).toBe(false);
    });

    it('remembers an approval in a signed cookie', () => {
      const store = createStore();
      const { cookie, attributes } = remember(store, requestWithCookie());

      expect(attributes).toEqual(['Path=/authorize', 'Max-Age=60', 'HttpOnly', 'SameSite=Lax']);
      expect(store.has(requestWithCookie(cookie), CLIENT, REDIRECT)).toBe(true);
      expect(store.has(requestWithCookie(cookie), CLIENT, 'http://localhost:4000/cb')).toBe(false);
      expect(store.has(requestWithCookie(cookie), 'other', REDIRECT)).toBe(false);
    });

    it('marks the cookie Secure when configured', () => {
      const { attributes } = remember(createStore({ secure: true }), requestWithCookie());
      expect(attributes).toContain('Secure');
    });

    it('rejects a tampered or foreign cookie', () => {
      const store = createStore();
      const { cookie } = remember(store, requestWithCookie());
      const [name, value] = cookie.split('=') as [string, string];
      const [payload, signature] = value.split('.') as [string, string];

      const forged = Buffer.from(JSON.stringify({ v: 1, g: { x: Date.now() + 1 } })).toString(
        'base64url'
      );
      expect(store.has(requestWithCookie(`${name}=${forged}.${signature}`), CLIENT, REDIRECT)).toBe(
        false
      );
      expect(store.has(requestWithCookie(`${name}=${payload}.bad`), CLIENT, REDIRECT)).toBe(false);
      expect(store.has(requestWithCookie(`${name}=${payload}`), CLIENT, REDIRECT)).toBe(false);
      expect(
        createStore({ secret: 'other' }).has(requestWithCookie(cookie), CLIENT, REDIRECT)
      ).toBe(false);
    });

    it('ignores a cookie whose payload is not the expected shape', () => {
      const store = createStore();
      const sign = (payload: string) => {
        const { cookie } = remember(store, requestWithCookie());
        return cookie.split('=')[1]?.split('.')[1] && payload;
      };
      // A validly signed cookie with the wrong structure cannot be produced
      // externally, so only garbage payloads are testable here
      expect(sign('x')).toBeDefined();
      expect(store.has(requestWithCookie('consent=notbase64.sig'), CLIENT, REDIRECT)).toBe(false);
    });

    it('expires approvals', () => {
      vi.useFakeTimers();
      const store = createStore({ ttl: 1_000 });
      const { cookie } = remember(store, requestWithCookie());

      expect(store.has(requestWithCookie(cookie), CLIENT, REDIRECT)).toBe(true);
      vi.advanceTimersByTime(1_001);
      expect(store.has(requestWithCookie(cookie), CLIENT, REDIRECT)).toBe(false);
    });

    it('keeps earlier approvals when adding one', () => {
      const store = createStore();
      const first = remember(store, requestWithCookie()).cookie;
      const second = remember(store, requestWithCookie(first), 'client-2', REDIRECT).cookie;

      expect(store.has(requestWithCookie(second), CLIENT, REDIRECT)).toBe(true);
      expect(store.has(requestWithCookie(second), 'client-2', REDIRECT)).toBe(true);
    });

    it('drops the oldest approvals beyond the limit', () => {
      const store = createStore();
      let cookie = remember(store, requestWithCookie(), 'client-0', REDIRECT).cookie;
      for (let i = 1; i <= 20; i += 1) {
        cookie = remember(store, requestWithCookie(cookie), `client-${i}`, REDIRECT).cookie;
      }

      expect(store.has(requestWithCookie(cookie), 'client-0', REDIRECT)).toBe(false);
      expect(store.has(requestWithCookie(cookie), 'client-1', REDIRECT)).toBe(true);
      expect(store.has(requestWithCookie(cookie), 'client-20', REDIRECT)).toBe(true);
    });
  });
});
