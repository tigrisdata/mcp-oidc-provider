# mcp-oidc-provider

Framework-agnostic OIDC provider for MCP (Model Context Protocol) servers with pluggable identity providers.

## Features

- **Pluggable Identity Providers**: Generic interface for any OIDC-compliant IdP
- **Built-in Auth0 Support**: Ready-to-use Auth0 client implementation
- **Express Adapter**: Full Express.js integration included
- **MCP SDK Integration**: Works seamlessly with `@modelcontextprotocol/sdk`
- **Dynamic Client Registration**: Automatic DCR support for MCP clients
- **Keyv Storage**: Compatible with any Keyv backend (Tigris, Redis, MongoDB, etc.)
- **TypeScript First**: Full type definitions included

## Installation

```bash
npm install mcp-oidc-provider keyv
```

For Auth0 support (recommended):
```bash
npm install mcp-oidc-provider keyv openid-client
```

## Quick Start

### Option 1: Standalone OIDC Server with MCP SDK (Recommended)

This approach runs a separate OIDC server and uses the MCP SDK's `ProxyOAuthServerProvider` for your MCP server.

```typescript
import express from 'express';
import { Keyv } from 'keyv';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { mcpAuthRouter, ProxyOAuthServerProvider, requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth';

import { createOidcServer } from 'mcp-oidc-provider/express';
import { Auth0Client } from 'mcp-oidc-provider/auth0';
import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';

// Create a shared Keyv store
const store = new Keyv();

// 1. Create and start the OIDC server
const oidcServer = createOidcServer({
  idpClient: new Auth0Client({
    domain: process.env.AUTH0_DOMAIN!,
    clientId: process.env.AUTH0_CLIENT_ID!,
    clientSecret: process.env.AUTH0_CLIENT_SECRET!,
    redirectUri: 'http://localhost:4001/oauth/callback',
  }),
  store,
  secret: process.env.SESSION_SECRET!,
  port: 4001,
  baseUrl: 'http://localhost:4001',
});

await oidcServer.start();
console.log(`OIDC server running at ${oidcServer.baseUrl}`);

// 2. Create MCP server with SDK auth
const mcpApp = express();
const MCP_BASE_URL = 'http://localhost:3001';

// Get config for ProxyOAuthServerProvider
const { proxyOAuthServerProviderConfig, mcpRoutes, resourceMetadataUrl } = createMcpAuthProvider({
  oidcServer,
  store,
  mcpServerBaseUrl: MCP_BASE_URL,
});

// Create auth provider
const authProvider = new ProxyOAuthServerProvider(proxyOAuthServerProviderConfig);

// Mount routes (includes CORS, health check, and protected resource metadata)
mcpApp.use(mcpRoutes);

// Install MCP auth router
mcpApp.use(mcpAuthRouter({
  provider: authProvider,
  issuerUrl: new URL(oidcServer.baseUrl),
  baseUrl: new URL(MCP_BASE_URL),
}));

// Protected MCP endpoint
mcpApp.use(express.json());
mcpApp.post('/mcp', requireBearerAuth({ verifier: authProvider, resourceMetadataUrl }), async (req, res) => {
  // Your MCP handler here
});

mcpApp.listen(3001);
```

### Option 2: All-in-One Setup

For simpler deployments where OIDC and MCP run in the same Express app:

```typescript
import { Keyv } from 'keyv';
import { setupMcpExpress } from 'mcp-oidc-provider/express';
import { Auth0Client } from 'mcp-oidc-provider/auth0';

const { app, handleMcpRequest } = setupMcpExpress({
  idpClient: new Auth0Client({
    domain: process.env.AUTH0_DOMAIN!,
    clientId: process.env.AUTH0_CLIENT_ID!,
    clientSecret: process.env.AUTH0_CLIENT_SECRET!,
    redirectUri: `${process.env.BASE_URL}/oauth/callback`,
  }),
  store: new Keyv(),
  baseUrl: process.env.BASE_URL!,
  secret: process.env.SESSION_SECRET!,
});

// Handle MCP requests with authenticated user
handleMcpRequest(async (req, res, user) => {
  console.log('Authenticated user:', user.claims.email);
  // Your MCP server logic here
});

app.listen(3000);
```

## Package Exports

### Main Package (`mcp-oidc-provider`)

Core types and utilities:

```typescript
import {
  // Types
  type IdentityProviderClient,
  type AuthorizationParams,
  type TokenSet,
  type UserClaims,
  type OidcProviderConfig,
  // Utilities
  createConsoleLogger,
  generateJwks,
} from 'mcp-oidc-provider';
```

### Auth0 Client (`mcp-oidc-provider/auth0`)

```typescript
import { Auth0Client, type Auth0Config } from 'mcp-oidc-provider/auth0';
```

### Express Adapter (`mcp-oidc-provider/express`)

```typescript
import {
  // High-level APIs
  createOidcServer,      // Standalone OIDC server
  setupMcpExpress,       // All-in-one OIDC + MCP setup

  // Lower-level APIs
  createExpressAdapter,
  createExpressAuthMiddleware,
  KeyvSessionStore,
  createMcpCorsMiddleware,
} from 'mcp-oidc-provider/express';
```

### MCP Integration (`mcp-oidc-provider/mcp`)

```typescript
import {
  createMcpAuthProvider,
  InvalidTokenError,
  type McpAuthProviderOptions,
  type McpAuthProviderResult,
  type ProxyOAuthServerProviderConfig,
} from 'mcp-oidc-provider/mcp';
```

## Configuration

### createOidcServer Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `idpClient` | `IdentityProviderClient` | Yes | Identity provider client (e.g., Auth0Client) |
| `store` | `Keyv` | Yes | Keyv instance for storage |
| `secret` | `string` | Yes | Secret for signing cookies/sessions |
| `port` | `number` | No | Port to listen on (default: 4000) |
| `baseUrl` | `string` | No | Base URL of the OIDC server |
| `jwks` | `JWKS` | No | Custom JWKS for signing tokens |
| `isProduction` | `boolean` | No | Production mode flag |
| `sessionMaxAge` | `number` | No | Session max age in ms (default: 30 days) |
| `onListen` | `function` | No | Callback when server starts |

### createMcpAuthProvider Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `oidcServer` | `OidcServerResult` | Yes | OIDC server from createOidcServer |
| `store` | `Keyv` | Yes | Same Keyv instance used by OIDC server |
| `mcpServerBaseUrl` | `string` | Yes | Base URL of your MCP server |
| `mcpEndpointPath` | `string` | No | MCP endpoint path (default: '/mcp') |
| `scopesSupported` | `string[]` | No | Supported OAuth scopes |

### Auth0Config

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `domain` | `string` | Yes | Auth0 domain (e.g., 'tenant.auth0.com') |
| `clientId` | `string` | Yes | OAuth client ID |
| `clientSecret` | `string` | Yes | OAuth client secret |
| `redirectUri` | `string` | Yes | OAuth callback URL |
| `audience` | `string` | No | API audience for access tokens |

## Custom Identity Provider

Implement the `IdentityProviderClient` interface to support any OIDC-compliant identity provider:

```typescript
import type { IdentityProviderClient, AuthorizationParams, TokenSet, UserClaims } from 'mcp-oidc-provider';

class MyIdpClient implements IdentityProviderClient {
  async createAuthorizationUrl(scope: string): Promise<AuthorizationParams> {
    // Generate authorization URL with PKCE, state, and nonce
  }

  async exchangeCode(
    callbackUrl: string,
    codeVerifier: string,
    expectedState: string,
    expectedNonce?: string
  ): Promise<TokenSet> {
    // Exchange authorization code for tokens
  }

  async refreshToken(refreshToken: string): Promise<TokenSet> {
    // Refresh access token
  }

  parseIdToken(idToken: string): UserClaims {
    // Decode ID token claims
  }

  // Optional: Extract custom data from claims
  extractCustomData?(claims: UserClaims): Record<string, unknown> | undefined {
    // Return any custom data you want stored in the user session
  }
}
```

## Storage Backends

The package uses Keyv for storage abstraction. You can use any Keyv-compatible backend:

### In-Memory (Development)

```typescript
import { Keyv } from 'keyv';
const store = new Keyv();
```

### Redis

```typescript
import { Keyv } from 'keyv';
import KeyvRedis from '@keyv/redis';

const store = new Keyv({
  store: new KeyvRedis('redis://localhost:6379'),
});
```

### Tigris

```typescript
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';

const store = new Keyv({
  store: new KeyvTigris(),
});
```

## OIDC Endpoints

When using `createOidcServer`, the following endpoints are available:

| Endpoint | Description |
|----------|-------------|
| `GET /authorize` | Authorization endpoint |
| `POST /token` | Token endpoint |
| `POST /token/revocation` | Token revocation endpoint |
| `POST /register` | Dynamic Client Registration |
| `GET /jwks` | JSON Web Key Set |
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /oauth/callback` | IdP callback handler |
| `GET /health` | Health check |

## MCP Client Support

The provider automatically handles Dynamic Client Registration for MCP clients, including support for custom protocol URIs:

- `cursor://` - Cursor IDE
- `vscode://` - VS Code
- `windsurf://` - Windsurf

## License

MIT
