/**
 * Shared test constants to eliminate magic strings and numbers.
 */

// Timeouts
export const TEST_TIMEOUT_MS = 30000;
export const TEST_TOKEN_TTL_SECONDS = 3600;
export const TEST_SESSION_TTL_MS = 86400000; // 1 day

// URLs
export const TEST_ISSUER = 'https://auth.example.com';
export const TEST_BASE_URL = 'http://localhost:3000';
export const TEST_CALLBACK_URL = 'http://localhost:3000/callback';
export const TEST_JWKS_URI = 'https://auth.example.com/.well-known/jwks.json';

// IDs
export const TEST_CLIENT_ID = 'client-123';
export const TEST_CLIENT_SECRET = 'secret-123';
export const TEST_USER_ID = 'user-123';
export const TEST_SESSION_ID = 'session-123';

// Test tokens
export const TEST_ACCESS_TOKEN = 'access-token';
export const TEST_ID_TOKEN = 'id-token';
export const TEST_REFRESH_TOKEN = 'refresh-token';
export const TEST_STATE = 'state-123';
export const TEST_NONCE = 'nonce-123';
export const TEST_CODE_VERIFIER = 'verifier-123';
export const TEST_AUTH_CODE = 'auth-code-123';

// Test secrets
export const TEST_SECRET = 'test-secret';

// Test user claims
export const TEST_EMAIL = 'user@example.com';
