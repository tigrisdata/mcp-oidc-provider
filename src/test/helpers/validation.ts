import { expect } from 'vitest';

/**
 * Validation rule types inspired by AWS MCP testing patterns.
 * Supports exact match, contains, and regex patterns.
 */
export type ValidationRule =
  | { type: 'exact'; value: unknown }
  | { type: 'contains'; value: string }
  | { type: 'regex'; pattern: RegExp }
  | { type: 'defined' }
  | { type: 'truthy' }
  | { type: 'type'; expected: string };

/**
 * Validates a value against a validation rule.
 */
export function validateValue(actual: unknown, rule: ValidationRule): boolean {
  switch (rule.type) {
    case 'exact':
      return actual === rule.value;
    case 'contains':
      return typeof actual === 'string' && actual.includes(rule.value);
    case 'regex':
      return typeof actual === 'string' && rule.pattern.test(actual);
    case 'defined':
      return actual !== undefined && actual !== null;
    case 'truthy':
      return Boolean(actual);
    case 'type':
      return typeof actual === rule.expected;
    default:
      return false;
  }
}

/**
 * Standard error response format (inspired by AWS MCP patterns).
 * Ensures consistent error responses across the codebase.
 */
export interface StandardErrorResponse {
  error: string;
  message?: string;
  code?: string;
}

/**
 * Validates that an error response matches the standard format.
 */
export function expectStandardError(
  response: unknown,
  expectedError?: string,
  expectedMessage?: string
): void {
  expect(response).toBeDefined();
  expect(typeof response).toBe('object');

  const errorResponse = response as StandardErrorResponse;
  expect(errorResponse.error).toBeDefined();

  if (expectedError) {
    expect(errorResponse.error).toBe(expectedError);
  }

  if (expectedMessage) {
    expect(errorResponse.message).toBe(expectedMessage);
  }
}

/**
 * Validates a successful HTTP response.
 */
export function expectSuccessResponse(
  response: { status: number; body?: unknown },
  expectedStatus = 200
): void {
  expect(response.status).toBe(expectedStatus);
}

/**
 * Validates an error HTTP response.
 */
export function expectErrorResponse(
  response: { status: number; body?: unknown },
  expectedStatus: number,
  expectedError?: string
): void {
  expect(response.status).toBe(expectedStatus);
  if (expectedError && response.body) {
    expectStandardError(response.body, expectedError);
  }
}

/**
 * Validates that a mock function was called with specific arguments.
 * Inspired by AWS MCP's call_args inspection pattern.
 */
export function expectCalledWith(
  mockFn: { mock: { calls: unknown[][] } },
  expectedArgs: unknown[],
  callIndex = 0
): void {
  expect(mockFn.mock.calls.length).toBeGreaterThan(callIndex);
  const actualArgs = mockFn.mock.calls[callIndex];

  expectedArgs.forEach((expected, index) => {
    if (expected !== undefined) {
      expect(actualArgs?.[index]).toEqual(expected);
    }
  });
}

/**
 * Validates OAuth/OIDC token response format.
 */
export function expectValidTokenResponse(response: unknown): void {
  expect(response).toBeDefined();
  expect(typeof response).toBe('object');

  const tokenResponse = response as Record<string, unknown>;
  expect(tokenResponse.accessToken ?? tokenResponse.access_token).toBeDefined();
}

/**
 * Validates user claims format.
 */
export function expectValidUserClaims(claims: unknown): void {
  expect(claims).toBeDefined();
  expect(typeof claims).toBe('object');

  const userClaims = claims as Record<string, unknown>;
  expect(userClaims.sub).toBeDefined();
}
