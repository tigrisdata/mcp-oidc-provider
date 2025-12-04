# Standalone OIDC Server Example

This example demonstrates the **recommended architecture** for production deployments: running the OIDC provider as a standalone server and using the MCP SDK's `ProxyOAuthServerProvider` for your MCP server.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│   MCP Server    │
│ (Cursor, etc.)  │     │   (port 3001)   │
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
                        │     Auth0       │
                        │   (Identity)    │
                        └─────────────────┘
```

**Benefits of this architecture:**
- OIDC server can be scaled independently
- Multiple MCP servers can share the same OIDC server
- Cleaner separation of concerns
- Full MCP SDK auth integration

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy the example environment file and configure it:

```bash
cp .env.example .env
```

3. Configure your Auth0 application:
   - Create an application in Auth0
   - Set the callback URL to `http://localhost:4001/oauth/callback`
   - Copy the domain, client ID, and client secret to `.env`

4. Run the development server:

```bash
npm run dev
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OIDC_PORT` | OIDC server port (default: 4001) |
| `MCP_PORT` | MCP server port (default: 3001) |
| `OIDC_BASE_URL` | Public URL of the OIDC server |
| `MCP_BASE_URL` | Public URL of the MCP server |
| `SESSION_SECRET` | Secret for session encryption |
| `AUTH0_DOMAIN` | Your Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret |
| `AUTH0_AUDIENCE` | Optional API audience |

## Endpoints

### OIDC Server (port 4001)

| Endpoint | Description |
|----------|-------------|
| `GET /authorize` | Authorization endpoint |
| `POST /token` | Token endpoint |
| `POST /register` | Dynamic Client Registration |
| `GET /jwks` | JSON Web Key Set |
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /oauth/callback` | Auth0 callback handler |
| `GET /health` | Health check |

### MCP Server (port 3001)

| Endpoint | Description |
|----------|-------------|
| `POST /mcp` | MCP endpoint (requires authentication) |
| `GET /.well-known/oauth-authorization-server` | OAuth metadata |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `GET /health` | Health check |

## Key Components

This example uses:

- **`createOidcServer`** from `mcp-oidc-provider/express` - Standalone OIDC server
- **`createMcpAuthProvider`** from `mcp-oidc-provider/mcp` - MCP SDK integration helper
- **`ProxyOAuthServerProvider`** from MCP SDK - Proxies OAuth requests to OIDC server
- **`mcpAuthRouter`** from MCP SDK - OAuth routes for MCP server
- **`requireBearerAuth`** from MCP SDK - Bearer token middleware

## Usage

Once running, configure your MCP client (Cursor, VS Code, etc.) to connect to:

```
http://localhost:3001/mcp
```

After authenticating, you can use the `whoami` tool to see your user information.
