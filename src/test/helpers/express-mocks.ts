import { vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import type { AuthenticatedUser } from '../../types.js';
import {
  TEST_USER_ID,
  TEST_EMAIL,
  TEST_ACCESS_TOKEN,
  TEST_ID_TOKEN,
  TEST_REFRESH_TOKEN,
} from '../constants.js';

/**
 * Creates a mock Express Request object for testing.
 */
export function createMockRequest(overrides?: Partial<Request>): Partial<Request> {
  return {
    headers: {},
    method: 'GET',
    protocol: 'https',
    get: vi.fn((name: string) => {
      if (name === 'host') return 'example.com';
      return undefined;
    }),
    ...overrides,
  };
}

/**
 * Creates a mock Express Response object for testing.
 * Returns both the response object and a headers map for inspection.
 */
export function createMockResponse(): {
  res: Partial<Response>;
  headers: Record<string, string>;
} {
  const headers: Record<string, string> = {};

  const res: Partial<Response> = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    end: vi.fn(),
    setHeader: vi.fn((key: string, value: string) => {
      headers[key] = value;
      return res as Response;
    }),
  };

  return { res, headers };
}

/**
 * Creates a mock NextFunction for testing.
 */
export function createMockNext(): NextFunction {
  return vi.fn();
}

/**
 * Creates a mock authenticated user for testing.
 */
export function createMockUser(overrides?: Partial<AuthenticatedUser>): AuthenticatedUser {
  return {
    accountId: `account-${TEST_USER_ID}`,
    userId: TEST_USER_ID,
    claims: { sub: TEST_USER_ID, email: TEST_EMAIL },
    tokenSet: {
      accessToken: TEST_ACCESS_TOKEN,
      idToken: TEST_ID_TOKEN,
      refreshToken: TEST_REFRESH_TOKEN,
    },
    ...overrides,
  };
}

/**
 * Creates a JWT with a specific expiration time for testing auto-refresh.
 */
export function createExpiringJwt(secondsUntilExpiry: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: TEST_USER_ID,
      exp: Math.floor(Date.now() / 1000) + secondsUntilExpiry,
    })
  ).toString('base64url');
  return `${header}.${payload}.signature`;
}
