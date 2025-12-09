// Integrated setup - OIDC + MCP in one Express app
export { setupMcpExpress } from './setup.js';
export type { McpExpressSetupOptions, McpExpressSetupResult, McpRequestHandler } from './setup.js';

// Standalone OIDC server - use with MCP SDK's ProxyOAuthServerProvider
export { createOidcServer } from './server.js';
export type { OidcServerOptions, OidcServerResult } from './server.js';

// Lower-level APIs for advanced use cases
export {
  createExpressAdapter,
  createCompleteExpressRouter,
  isOidcProviderRoute,
} from './adapter.js';
export type { ExpressAdapterOptions, ExpressAdapterResult } from './adapter.js';

export { createExpressAuthMiddleware } from './middleware.js';
export type { ExpressAuthMiddlewareOptions } from './middleware.js';

export { createExpressHttpContext } from './http-context.js';

export { KeyvSessionStore } from './session-store.js';

export {
  createMcpCorsMiddleware,
  getMcpCorsOptions,
  createMcpHealthMiddleware,
  MCP_SESSION_ID_HEADER,
  MCP_INSPECTOR_ORIGIN,
  DEFAULT_MCP_ALLOWED_HEADERS,
  DEFAULT_MCP_EXPOSED_HEADERS,
} from './cors.js';
export type { McpCorsOptions, McpHealthOptions, HealthCheckResponse } from './cors.js';
