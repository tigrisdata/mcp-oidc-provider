# mcp-oidc-provider

Framework-agnostic OIDC provider for MCP (Model Context Protocol) servers with pluggable identity providers.

## Features

- **Framework Agnostic**: Core implementation works with any Node.js web framework
- **Pluggable Identity Providers**: Generic interface for any OIDC-compliant IdP
- **Built-in Auth0 Support**: Ready-to-use Auth0 client implementation
- **Express Adapter**: Full Express.js integration included
- **Keyv Storage**: Compatible with any Keyv backend (Redis, MongoDB, Tigris, etc.)
- **MCP Client Support**: Automatic handling of custom protocol URIs (cursor://, vscode://, windsurf://)
- **TypeScript First**: Full type definitions included

## Installation

```bash
npm install mcp-oidc-provider keyv
```

For Auth0 support:
```bash
npm install mcp-oidc-provider keyv openid-client
```

## Quick Start

### Basic Setup with Express and Auth0

```typescript
import express from 'express';
import session from 'express-session';
import Keyv from 'keyv';
import { createOidcProvider } from 'mcp-oidc-provider';
import { Auth0Client } from 'mcp-oidc-provider/auth0';
import {
  createExpressAdapter,
  createExpressAuthMiddleware,
  KeyvSessionStore,
} from 'mcp-oidc-provider/express';

const app = express();

// Create a Keyv store factory
const createStore = <T>(namespace: string, ttl?: number) => {
  return new Keyv<T>({ namespace, ttl });
};

// Create Auth0 client
const auth0Client = new Auth0Client({
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  redirectUri: `${process.env.BASE_URL}/oauth/callback`,
  audience: process.env.AUTH0_AUDIENCE,
});

// Create OIDC provider
const oidcProvider = createOidcProvider({
  issuer: process.env.BASE_URL!,
  idpClient: auth0Client,
  storage: createStore,
  cookieSecrets: [process.env.COOKIE_SECRET!],
  isProduction: process.env.NODE_ENV === 'production',
});

// Setup Express session with Keyv store
app.use(session({
  store: new KeyvSessionStore(new Keyv({ namespace: 'sessions' })),
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
}));

// Create Express adapter
const { routes, providerCallback } = createExpressAdapter(oidcProvider);

// Mount OAuth routes
app.use('/oauth', routes);
app.use('/', providerCallback());

// Protected routes with auth middleware
const authMiddleware = createExpressAuthMiddleware(oidcProvider);
app.use('/api', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

## Package Exports

### Main Package (`mcp-oidc-provider`)

```typescript
import {
  createOidcProvider,
  createSessionStore,
  createExtendedSessionStore,
  createConsoleLogger,
  // Types
  type OidcProviderConfig,
  type OidcProvider,
  type IdentityProviderClient,
  // ... and more
} from 'mcp-oidc-provider';
```

### Auth0 Client (`mcp-oidc-provider/auth0`)

```typescript
import { Auth0Client, type Auth0Config } from 'mcp-oidc-provider/auth0';
```

### Express Adapter (`mcp-oidc-provider/express`)

```typescript
import {
  createExpressAdapter,
  createCompleteExpressRouter,
  createExpressAuthMiddleware,
  createOptionalAuthMiddleware,
  KeyvSessionStore,
} from 'mcp-oidc-provider/express';
```

## Configuration

### OidcProviderConfig

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `issuer` | `string` | Yes | Your server's base URL |
| `idpClient` | `IdentityProviderClient` | Yes | Identity provider client instance |
| `storage` | `StoreFactory` | Yes | Factory function for creating stores |
| `cookieSecrets` | `string[]` | Yes | Secrets for signing cookies |
| `callbackPath` | `string` | No | IdP callback path (default: '/callback') |
| `ttl` | `object` | No | Token TTL configuration |
| `scopes` | `string[]` | No | Supported OAuth scopes |
| `isProduction` | `boolean` | No | Production mode flag |
| `allowedClientProtocols` | `string[]` | No | Allowed custom URI protocols |
| `claims` | `object` | No | Custom claims configuration |
| `logger` | `Logger` | No | Custom logger instance |

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
import Keyv from 'keyv';

const createStore = <T>(namespace: string, ttl?: number) => {
  return new Keyv<T>({ namespace, ttl });
};
```

### Redis

```typescript
import Keyv from 'keyv';
import KeyvRedis from '@keyv/redis';

const createStore = <T>(namespace: string, ttl?: number) => {
  return new Keyv<T>({
    store: new KeyvRedis('redis://localhost:6379'),
    namespace,
    ttl,
  });
};
```

### Tigris

```typescript
import Keyv from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';

const createStore = <T>(namespace: string, ttl?: number) => {
  return new Keyv<T>({
    store: new KeyvTigris({ logicalDatabase: 'my-app' }),
    namespace,
    ttl,
  });
};
```

## MCP Client Support

The provider automatically allows custom protocol URIs for known MCP clients:

- `cursor://` - Cursor IDE
- `vscode://` - VS Code
- `windsurf://` - Windsurf

To add additional protocols:

```typescript
const provider = createOidcProvider({
  // ...
  allowedClientProtocols: ['cursor://', 'vscode://', 'windsurf://', 'myapp://'],
});
```

## API Reference

### createOidcProvider(config)

Creates a new OIDC provider instance.

Returns: `OidcProvider`

```typescript
interface OidcProvider {
  provider: Provider;              // Underlying oidc-provider instance
  sessionStore: SessionStore;      // User session store
  handleInteraction(ctx): Promise<void>;  // Handle login/consent flow
  handleCallback(ctx): Promise<void>;     // Handle IdP callback
  validateToken(token): Promise<TokenValidationResult>;  // Validate access token
  refreshIdpTokens(accountId): Promise<boolean>;         // Refresh IdP tokens
}
```

### createExpressAdapter(provider, options?)

Creates an Express adapter for the OIDC provider.

Returns: `ExpressAdapterResult`

```typescript
interface ExpressAdapterResult {
  routes: Router;                           // Custom OAuth routes
  providerCallback: () => RequestHandler;   // OIDC provider callback
  isProviderRoute: (path) => boolean;       // Check if path is provider route
}
```

### createExpressAuthMiddleware(provider, options?)

Creates an Express middleware for token validation.

Options:
- `autoRefresh`: Auto-refresh IdP tokens (default: true)
- `refreshBufferSeconds`: Seconds before expiry to trigger refresh (default: 300)
- `logger`: Custom logger instance

## License

MIT
