import { vi } from 'vitest';
import type { IOidcClient } from '../../types.js';
import {
  TEST_ISSUER,
  TEST_ACCESS_TOKEN,
  TEST_ID_TOKEN,
  TEST_REFRESH_TOKEN,
  TEST_TOKEN_TTL_SECONDS,
  TEST_STATE,
  TEST_NONCE,
  TEST_CODE_VERIFIER,
  TEST_USER_ID,
  TEST_EMAIL,
} from '../constants.js';

/**
 * Creates a mock OIDC client for testing.
 * All methods are pre-configured with sensible defaults that can be overridden.
 */
export function createMockIdpClient(overrides?: Partial<IOidcClient>): IOidcClient {
  return {
    createAuthorizationUrl: vi.fn().mockResolvedValue({
      authorizationUrl: `${TEST_ISSUER}/authorize`,
      state: TEST_STATE,
      nonce: TEST_NONCE,
      codeVerifier: TEST_CODE_VERIFIER,
    }),
    exchangeCode: vi.fn().mockResolvedValue({
      accessToken: TEST_ACCESS_TOKEN,
      idToken: TEST_ID_TOKEN,
      refreshToken: TEST_REFRESH_TOKEN,
      expiresIn: TEST_TOKEN_TTL_SECONDS,
    }),
    refreshToken: vi.fn().mockResolvedValue({
      accessToken: `new-${TEST_ACCESS_TOKEN}`,
      idToken: `new-${TEST_ID_TOKEN}`,
      refreshToken: `new-${TEST_REFRESH_TOKEN}`,
      expiresIn: TEST_TOKEN_TTL_SECONDS,
    }),
    parseIdToken: vi.fn().mockReturnValue({
      sub: TEST_USER_ID,
      email: TEST_EMAIL,
    }),
    extractCustomData: vi.fn().mockReturnValue(undefined),
    ...overrides,
  };
}

/**
 * Creates mock token set data for testing.
 */
export function createMockTokenSet(
  overrides?: Partial<{
    accessToken: string;
    idToken: string;
    refreshToken: string;
    expiresIn: number;
  }>
) {
  return {
    accessToken: TEST_ACCESS_TOKEN,
    idToken: TEST_ID_TOKEN,
    refreshToken: TEST_REFRESH_TOKEN,
    expiresIn: TEST_TOKEN_TTL_SECONDS,
    ...overrides,
  };
}

/**
 * Creates mock user claims for testing.
 */
export function createMockClaims(overrides?: Record<string, unknown>) {
  return {
    sub: TEST_USER_ID,
    email: TEST_EMAIL,
    ...overrides,
  };
}
