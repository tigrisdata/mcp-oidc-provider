// Main setup function - the recommended way to use this package
export { setupMcpExpress } from './setup.js';
export type { McpExpressSetupOptions, McpExpressSetupResult, McpRequestHandler } from './setup.js';

// Lower-level APIs for advanced use cases
export {
  createExpressAdapter,
  createCompleteExpressRouter,
  isOidcProviderRoute,
} from './adapter.js';
export type { ExpressAdapterOptions, ExpressAdapterResult } from './adapter.js';

export { createExpressAuthMiddleware, createOptionalAuthMiddleware } from './middleware.js';
export type { ExpressAuthMiddlewareOptions } from './middleware.js';

export { createExpressHttpContext } from './http-context.js';

export { KeyvSessionStore } from './session-store.js';

export {
  createMcpCorsMiddleware,
  getMcpCorsOptions,
  MCP_SESSION_ID_HEADER,
  MCP_INSPECTOR_ORIGIN,
  DEFAULT_MCP_ALLOWED_HEADERS,
  DEFAULT_MCP_EXPOSED_HEADERS,
} from './cors.js';
export type { McpCorsOptions } from './cors.js';
