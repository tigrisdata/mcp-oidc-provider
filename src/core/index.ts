export { createOidcProvider } from './provider.js';
export { createSessionStore, createExtendedSessionStore } from './session-store.js';
export type { ExtendedSessionStore } from './session-store.js';
export { createOidcAdapterFactory } from './oidc-adapter.js';
export type { OidcAdapterFactory } from './oidc-adapter.js';

// Config exports
export {
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_ID_TOKEN_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_INTERACTION_SESSION_TTL_MS,
  DEFAULT_USER_SESSION_TTL_MS,
  DEFAULT_SCOPES,
  DEFAULT_CLAIMS,
  DEFAULT_ROUTES,
  DEFAULT_ALLOWED_CLIENT_PROTOCOLS,
} from './config.js';
