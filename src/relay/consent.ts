/**
 * Remembered consent decisions, stored in a signed cookie bound to the client
 * and its redirect URI.
 * @internal
 */

import { createHmac, hkdfSync } from 'node:crypto';
import type { Request, Response } from 'express';
import { safeEqual, sha256 } from './storage.js';

/** Most recent approvals kept in the cookie. */
const MAX_GRANTS = 20;

interface ConsentPayload {
  v: 1;
  /** Approval expiry (ms since epoch) by client key. */
  g: Record<string, number>;
}

export interface ConsentStoreOptions {
  cookieName: string;
  /** Signing key material. */
  secret: string;
  /** Approval lifetime in milliseconds. */
  ttl: number;
  secure: boolean;
}

/** Derive a signing key from the upstream client secret when none is configured. */
export function deriveConsentSecret(clientSecret: string): string {
  return Buffer.from(
    hkdfSync('sha256', clientSecret, 'mcp-oidc-provider', 'consent-cookie', 32)
  ).toString('base64url');
}

/** Key under which an approval is stored: the client and where its codes go. */
export function consentKey(clientId: string, redirectUri: string): string {
  return sha256(`${clientId}\n${redirectUri}`).slice(0, 22);
}

/** Parse the `Cookie` header. */
export function parseCookies(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name && !(name in cookies)) {
      try {
        cookies[name] = decodeURIComponent(value);
      } catch {
        cookies[name] = value;
      }
    }
  }
  return cookies;
}

/** Signed-cookie store for consent decisions. */
export class ConsentStore {
  private readonly options: ConsentStoreOptions;

  constructor(options: ConsentStoreOptions) {
    this.options = options;
  }

  private sign(payload: string): string {
    return createHmac('sha256', this.options.secret).update(payload).digest('base64url');
  }

  private read(req: Request): ConsentPayload {
    const empty: ConsentPayload = { v: 1, g: {} };
    const raw = parseCookies(req.headers.cookie)[this.options.cookieName];
    if (!raw) return empty;
    const [payload, signature] = raw.split('.');
    if (!payload || !signature || !safeEqual(this.sign(payload), signature)) return empty;
    try {
      const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString()) as ConsentPayload;
      if (parsed.v !== 1 || typeof parsed.g !== 'object' || parsed.g === null) return empty;
      return parsed;
    } catch {
      return empty;
    }
  }

  /** Whether the user already approved this client and redirect URI. */
  has(req: Request, clientId: string, redirectUri: string): boolean {
    const expiresAt = this.read(req).g[consentKey(clientId, redirectUri)];
    return typeof expiresAt === 'number' && expiresAt > Date.now();
  }

  /** Remember an approval; sets the cookie on the response. */
  remember(req: Request, res: Response, clientId: string, redirectUri: string): void {
    const now = Date.now();
    const grants = Object.entries(this.read(req).g).filter(([, expiresAt]) => expiresAt > now);
    grants.push([consentKey(clientId, redirectUri), now + this.options.ttl]);
    // Keep the newest approvals if the cookie would grow without bound
    const kept = Object.fromEntries(grants.slice(-MAX_GRANTS));
    const payload = Buffer.from(JSON.stringify({ v: 1, g: kept })).toString('base64url');
    const value = `${payload}.${this.sign(payload)}`;
    const attributes = [
      `${this.options.cookieName}=${value}`,
      'Path=/authorize',
      `Max-Age=${Math.floor(this.options.ttl / 1000)}`,
      'HttpOnly',
      'SameSite=Lax',
    ];
    if (this.options.secure) attributes.push('Secure');
    res.append('Set-Cookie', attributes.join('; '));
  }
}
