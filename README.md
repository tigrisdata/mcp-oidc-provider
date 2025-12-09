# mcp-oidc-provider

OIDC provider for MCP (Model Context Protocol) servers with support for any OIDC-compliant identity provider.

Implementing a [remote hosted MCP server](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers) requires [implementing MCP Authorization Protocol](https://modelcontextprotocol.io/specification/draft/basic/authorization). In theory, this is straightforward because modern applications either implement OAuth specs themselves or use an OAuth-compliant IdP like Auth0, Clerk, Okta, or Keycloak. [Long story short](https://www.tigrisdata.com/blog/mcp-oauth/), using your own IdP as-is imposes many limitations.

This package takes care of those limitations for you so you can focus on implementing your tools, resources, and prompts instead of spending hours investigating why your implementation doesn't work with Cursor or logs you out from Claude every few hours.

This package allows you to run either in standalone mode or integrate it into your MCP implementation. It works with any OIDC-compliant identity provider like Auth0, Clerk, Okta, Keycloak, Azure AD, Google, and more.

It uses different packages under the hood to glue everything together:

| Package           | Purpose                                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `oidc-provider`   | Core OIDC/OAuth 2.0 server implementation. Handles authorization, token issuance, JWKS, client registration, and all OAuth flows |
| `openid-client`   | OAuth 2.0/OIDC client library. Used by OidcClient to communicate with upstream identity providers via OIDC Discovery             |
| `jose`            | JWT signing/verification and JWKS generation. Used for access tokens and ID tokens                                               |
| `keyv`            | Universal key-value storage abstraction. Used for sessions, tokens, grants, and OIDC adapter data                                |
| `express`         | Web framework for the Express adapter. Provides routing, middleware, and HTTP handling                                           |
| `express-session` | Session management for Express. Stores login state during OAuth flows                                                            |

## Installation

```bash
npm install mcp-oidc-provider keyv openid-client
```

## Generating JWKS

For production, generate and persist signing keys:

```bash
npx mcp-oidc-generate-jwks --pretty
```

Store the output securely and provide it via the `jwks` option or `JWKS` environment variable.

## Quick Start

### Option 1: Standalone OIDC Server

That is useful if you already have your MCP implementation in a different stack than express js. You can have the implementation in nextjs, then you can run this server standalone and proxy the Auth requests to it using the MCP SDK's `ProxyOAuthServerProvider`. See the [standalone-oidc example](./example/standalone-oidc).

Both servers must share the same persistent Keyv store (e.g., Tigris, Redis) so the MCP server can look up tokens issued by the OIDC server.

**auth.ts** - OIDC Server (port 4001)

```typescript
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { createOidcServer } from 'mcp-oidc-provider/express';
import { OidcClient, type JWKS } from 'mcp-oidc-provider';

const OIDC_PORT = 4001;
const OIDC_BASE_URL = process.env.OIDC_BASE_URL ?? `http://localhost:${OIDC_PORT}`;

// Use a persistent store so both servers can access the same data
const store = new Keyv({ store: new KeyvTigris() });

// Parse JWKS from environment variable (required for production)
const jwks: JWKS | undefined = process.env.JWKS ? JSON.parse(process.env.JWKS) : undefined;

const oidcServer = createOidcServer({
  idpClient: new OidcClient({
    issuer: 'https://your-tenant.auth0.com', // or any OIDC issuer
    clientId: process.env.OIDC_CLIENT_ID!,
    clientSecret: process.env.OIDC_CLIENT_SECRET!,
    redirectUri: `${OIDC_BASE_URL}/oauth/callback`,
  }),
  store,
  secret: process.env.SESSION_SECRET!,
  port: OIDC_PORT,
  baseUrl: OIDC_BASE_URL,
  jwks,
});

await oidcServer.start();
```

**mcp.ts** - MCP Server (port 3001)

```typescript
import express from 'express';
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';

const OIDC_BASE_URL = process.env.OIDC_BASE_URL ?? 'http://localhost:4001';
const MCP_PORT = 3001;
const MCP_BASE_URL = process.env.MCP_BASE_URL ?? `http://localhost:${MCP_PORT}`;

// Same persistent store as the OIDC server
const store = new Keyv({ store: new KeyvTigris() });

const mcpApp = express();

// Get config for ProxyOAuthServerProvider
const { proxyOAuthServerProviderConfig, mcpRoutes, resourceMetadataUrl } = createMcpAuthProvider({
  oidcBaseUrl: OIDC_BASE_URL,
  store,
  mcpServerBaseUrl: MCP_BASE_URL,
});

// Create auth provider
const authProvider = new ProxyOAuthServerProvider(proxyOAuthServerProviderConfig);

// Mount routes (includes CORS, health check, and protected resource metadata)
mcpApp.use(mcpRoutes);

// Install MCP auth router
mcpApp.use(
  mcpAuthRouter({
    provider: authProvider,
    issuerUrl: new URL(OIDC_BASE_URL),
    baseUrl: new URL(MCP_BASE_URL),
  })
);

// Protected MCP endpoint
mcpApp.use(express.json());
mcpApp.post(
  '/mcp',
  requireBearerAuth({ verifier: authProvider, resourceMetadataUrl }),
  async (req, res) => {
    // Your MCP handler here
  }
);

mcpApp.listen(MCP_PORT);
```

### Option 2: MCP Server with Integrated OIDC

For simpler deployments where OIDC and MCP run in the same Express app. See the [mcp-integrated-oidc example](./example/mcp-integrated-oidc).

```typescript
import { Keyv } from 'keyv';
import { setupMcpExpress } from 'mcp-oidc-provider/express';
import { OidcClient, type JWKS } from 'mcp-oidc-provider';

// Parse JWKS from environment variable (required for production)
const jwks: JWKS | undefined = process.env.JWKS ? JSON.parse(process.env.JWKS) : undefined;

const { app, handleMcpRequest } = setupMcpExpress({
  idpClient: new OidcClient({
    issuer: 'https://your-tenant.auth0.com', // or any OIDC issuer
    clientId: process.env.OIDC_CLIENT_ID!,
    clientSecret: process.env.OIDC_CLIENT_SECRET!,
    redirectUri: `${process.env.BASE_URL}/oauth/callback`,
  }),
  store: new Keyv(),
  baseUrl: process.env.BASE_URL!,
  secret: process.env.SESSION_SECRET!,
  jwks,
});

// Handle MCP requests - user is available via req.user
handleMcpRequest(async (req, res) => {
  console.log('Authenticated user:', req.user);
  // Your MCP server logic here
});

app.listen(3000);
```

## Configuration

### OidcClientConfig

The `OidcClient` works with any OIDC-compliant identity provider. It uses [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) to automatically configure endpoints.

| Option                 | Type                                                           | Required | Description                                                       |
| ---------------------- | -------------------------------------------------------------- | -------- | ----------------------------------------------------------------- |
| `issuer`               | `string`                                                       | Yes      | OIDC issuer URL (e.g., `https://your-tenant.auth0.com`)           |
| `clientId`             | `string`                                                       | Yes      | OAuth client ID                                                   |
| `clientSecret`         | `string`                                                       | Yes      | OAuth client secret                                               |
| `redirectUri`          | `string`                                                       | Yes      | OAuth callback URL                                                |
| `scopes`               | `string`                                                       | No       | OAuth scopes (default: `openid email profile`)                    |
| `additionalAuthParams` | `Record<string, string>`                                       | No       | Additional authorization parameters (e.g., `{ audience: '...' }`) |
| `extractCustomData`    | `(claims: UserClaims) => Record<string, unknown> \| undefined` | No       | Extract provider-specific data from ID token claims               |

#### Provider Examples

```typescript
// Auth0
new OidcClient({
  issuer: 'https://your-tenant.auth0.com',
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
  scopes: 'openid email profile offline_access',
  additionalAuthParams: { audience: 'https://your-api.com' },
});

// Clerk (note: doesn't support offline_access)
new OidcClient({
  issuer: 'https://your-app.clerk.accounts.dev',
  clientId: process.env.CLERK_CLIENT_ID!,
  clientSecret: process.env.CLERK_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
  extractCustomData: (claims) => {
    if (claims['org_id']) {
      return {
        organization: {
          id: claims['org_id'],
          slug: claims['org_slug'],
          role: claims['org_role'],
        },
      };
    }
  },
});

// Okta
new OidcClient({
  issuer: 'https://your-domain.okta.com',
  clientId: process.env.OKTA_CLIENT_ID!,
  clientSecret: process.env.OKTA_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
  extractCustomData: (claims) => {
    if (claims['groups']) {
      return { groups: claims['groups'] };
    }
  },
});

// Keycloak
new OidcClient({
  issuer: 'https://keycloak.example.com/realms/my-realm',
  clientId: process.env.KEYCLOAK_CLIENT_ID!,
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
});

// Microsoft Azure AD
new OidcClient({
  issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
  clientId: process.env.AZURE_CLIENT_ID!,
  clientSecret: process.env.AZURE_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
});

// Google
new OidcClient({
  issuer: 'https://accounts.google.com',
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
});
```

### createOidcServer Options

| Option          | Type          | Required | Description                              |
| --------------- | ------------- | -------- | ---------------------------------------- |
| `idpClient`     | `IOidcClient` | Yes      | OIDC client instance                     |
| `store`         | `Keyv`        | Yes      | Keyv instance for storage                |
| `secret`        | `string`      | Yes      | Secret for signing cookies/sessions      |
| `port`          | `number`      | No       | Port to listen on (default: 4000)        |
| `baseUrl`       | `string`      | No       | Base URL of the OIDC server              |
| `jwks`          | `JWKS`        | No       | Custom JWKS for signing tokens           |
| `isProduction`  | `boolean`     | No       | Production mode flag                     |
| `sessionMaxAge` | `number`      | No       | Session max age in ms (default: 30 days) |
| `onListen`      | `function`    | No       | Callback when server starts              |

### createMcpAuthProvider Options

| Option             | Type       | Required | Description                                                 |
| ------------------ | ---------- | -------- | ----------------------------------------------------------- |
| `oidcBaseUrl`      | `string`   | Yes      | Base URL of the OIDC server (e.g., `http://localhost:4001`) |
| `store`            | `Keyv`     | Yes      | Same Keyv instance used by OIDC server                      |
| `mcpServerBaseUrl` | `string`   | Yes      | Base URL of your MCP server                                 |
| `mcpEndpointPath`  | `string`   | No       | MCP endpoint path (default: `/mcp`)                         |
| `scopesSupported`  | `string[]` | No       | Supported OAuth scopes                                      |

## Accessing IdP Tokens

When you need to call upstream APIs, use the `getIdpTokens` helper. It works with both authentication patterns:

```typescript
import { getIdpTokens } from 'mcp-oidc-provider/mcp';

// Works with setupMcpExpress (req.user)
handleMcpRequest(async (req, res) => {
  const tokens = getIdpTokens(req.user);
  if (tokens) {
    const userInfo = await fetch('https://my-api.com/api/userInfo', {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });
  }
});

// Works with requireBearerAuth (req.auth) - standalone OIDC setup
app.post('/mcp', requireBearerAuth({ verifier: authProvider }), async (req, res) => {
  const tokens = getIdpTokens(req.auth);
  if (tokens) {
    // tokens.accessToken - IdP access token
    // tokens.idToken - IdP ID token
    // tokens.refreshToken - IdP refresh token
  }
});
```

The `IdpTokenSet` interface:

```typescript
interface IdpTokenSet {
  accessToken: string; // Access token for calling IdP APIs
  idToken: string; // ID token containing user identity
  refreshToken: string; // Refresh token for obtaining new access tokens
  expiresAt?: number; // Unix timestamp when access token expires
}
```

You can also access tokens directly if preferred:

- `req.user.tokenSet` (with `setupMcpExpress`)
- `req.auth.extra.idpTokens` (with `requireBearerAuth`)

## Custom Identity Provider

For advanced use cases, you can implement the `IOidcClient` interface directly:

```typescript
import type { IOidcClient, AuthorizationParams, TokenSet, UserClaims } from 'mcp-oidc-provider';

class MyOidcClient implements IOidcClient {
  async createAuthorizationUrl(): Promise<AuthorizationParams> {
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

The package uses [Keyv](https://keyv.org/) for storage abstraction. The store is used to persist:

- **OAuth Clients** - Dynamically registered client applications (via DCR)
- **Authorization Codes** - Short-lived codes exchanged for tokens
- **Access Tokens** - Tokens used to authenticate API requests
- **Refresh Tokens** - Long-lived tokens used to obtain new access tokens
- **User Sessions** - Authenticated user information and IdP tokens
- **Interaction Sessions** - OAuth flow state (PKCE, nonce, redirect URIs)
- **Grants** - User consent records for client applications

You can use any Keyv-compatible backend. For production, use a persistent store like Tigris or Redis.

### In-Memory (Development Only)

```typescript
import { Keyv } from 'keyv';
const store = new Keyv();
```

> **Warning**: In-memory storage loses all data on restart and is not shared across server instances. Do not use in production or distributed deployments.

### [Tigris](https://www.npmjs.com/package/keyv-tigris) (Recommended for Production)

```typescript
import { Keyv } from 'keyv';
import { KeyvTigris } from 'keyv-tigris';

const store = new Keyv({
  store: new KeyvTigris(),
});
```

## OIDC Endpoints

When using `createOidcServer`, the following endpoints are available:

| Endpoint                                | Description                 |
| --------------------------------------- | --------------------------- |
| `GET /authorize`                        | Authorization endpoint      |
| `POST /token`                           | Token endpoint              |
| `POST /token/revocation`                | Token revocation endpoint   |
| `POST /register`                        | Dynamic Client Registration |
| `GET /jwks`                             | JSON Web Key Set            |
| `GET /.well-known/openid-configuration` | OIDC Discovery              |
| `GET /oauth/callback`                   | IdP callback handler        |
| `GET /health`                           | Health check                |

## MCP Client Support

The provider automatically handles Dynamic Client Registration for MCP clients, including support for custom protocol URIs:

- `cursor://` - Cursor IDE
- `vscode://` - VS Code
- `windsurf://` - Windsurf

## License

MIT
