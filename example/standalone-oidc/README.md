# Standalone OIDC Server Example

This example runs the OIDC provider as a standalone server, separate from your MCP server. Use this when you want to share the OIDC server across multiple MCP servers or when your MCP implementation is in a different stack (e.g., Next.js).

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│   MCP Server    │
│ (Cursor/Claude) │     │   (port 3001)   │
└─────────────────┘     └────────┬────────┘
                                │
                                │ Proxy OAuth
                                ▼
                       ┌─────────────────┐
                       │  OIDC Server    │
                       │  (port 4001)    │
                       └────────┬────────┘
                                │
                                │ OAuth Flow
                                ▼
                       ┌─────────────────┐
                       │  Auth0/Clerk    │
                       │   (Identity)    │
                       └─────────────────┘
```

**Benefits:**

- OIDC server can be scaled independently
- Multiple MCP servers can share the same OIDC server
- Cleaner separation of concerns

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy the example environment file and configure it:

```bash
cp .env.example .env
```

3. Configure your identity provider (Auth0 or Clerk):
   - Create an application in your IdP dashboard
   - Set the callback URL to `http://localhost:4001/oauth/callback`
   - Copy the credentials to `.env`

4. Run the development server:

```bash
npm run dev
```

## Environment Variables

| Variable              | Description                          |
| --------------------- | ------------------------------------ |
| `OIDC_PORT`           | OIDC server port (default: 4001)     |
| `MCP_PORT`            | MCP server port (default: 3001)      |
| `OIDC_BASE_URL`       | Public URL of the OIDC server        |
| `MCP_BASE_URL`        | Public URL of the MCP server         |
| `SESSION_SECRET`      | Secret for session encryption        |
| `AUTH0_DOMAIN`        | Auth0 tenant domain (if using Auth0) |
| `AUTH0_CLIENT_ID`     | Auth0 client ID (if using Auth0)     |
| `AUTH0_CLIENT_SECRET` | Auth0 client secret (if using Auth0) |
| `CLERK_DOMAIN`        | Clerk domain (if using Clerk)        |
| `CLERK_CLIENT_ID`     | Clerk client ID (if using Clerk)     |
| `CLERK_CLIENT_SECRET` | Clerk client secret (if using Clerk) |

## Endpoints

### OIDC Server (port 4001)

| Endpoint                                | Description                 |
| --------------------------------------- | --------------------------- |
| `GET /authorize`                        | Authorization endpoint      |
| `POST /token`                           | Token endpoint              |
| `POST /register`                        | Dynamic Client Registration |
| `GET /jwks`                             | JSON Web Key Set            |
| `GET /.well-known/openid-configuration` | OIDC Discovery              |
| `GET /oauth/callback`                   | IdP callback handler        |
| `GET /health`                           | Health check                |

### MCP Server (port 3001)

| Endpoint                                      | Description                  |
| --------------------------------------------- | ---------------------------- |
| `POST /mcp`                                   | MCP endpoint (requires auth) |
| `GET /.well-known/oauth-authorization-server` | OAuth metadata               |
| `GET /.well-known/oauth-protected-resource`   | Protected resource metadata  |
| `GET /health`                                 | Health check                 |

## Key Components

This example uses:

- **`createOidcServer`** from `mcp-oidc-provider/express` - Standalone OIDC server
- **`createMcpAuthProvider`** from `mcp-oidc-provider/mcp` - MCP SDK integration helper
- **`ProxyOAuthServerProvider`** from MCP SDK - Proxies OAuth requests to OIDC server
- **`mcpAuthRouter`** from MCP SDK - OAuth routes for MCP server
- **`requireBearerAuth`** from MCP SDK - Bearer token middleware

## Testing

Use the MCP Inspector to test the server:

```bash
npx @modelcontextprotocol/inspector
```

Connect to `http://localhost:3001/mcp`, authenticate, then use the `whoami` tool to verify your user information.
