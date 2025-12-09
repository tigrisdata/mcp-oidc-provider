# Integrated OIDC + MCP Server Example

This example runs OIDC and MCP in the same Express app. Use this for simpler deployments where you don't need to scale the OIDC server independently.

## Architecture

```
┌─────────────────┐     ┌─────────────────────────┐
│   MCP Client    │────▶│   Express Server        │
│ (Cursor/Claude) │     │   (port 3000)           │
└─────────────────┘     │  ┌───────────────────┐  │
                        │  │ OIDC Provider     │  │
                        │  └───────────────────┘  │
                        │  ┌───────────────────┐  │
                        │  │ MCP Server        │  │
                        │  └───────────────────┘  │
                        └────────────┬────────────┘
                                     │
                                     │ OAuth Flow
                                     ▼
                        ┌─────────────────────────┐
                        │      Auth0/Clerk        │
                        │       (Identity)        │
                        └─────────────────────────┘
```

**Benefits:**

- Single deployment unit
- Simpler configuration
- Easier to get started

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
   - Set the callback URL to `http://localhost:3000/oauth/callback`
   - Copy the credentials to `.env`

4. Run the development server:

```bash
npm run dev
```

## Environment Variables

| Variable              | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `PORT`                | Server port (default: 3000)                            |
| `BASE_URL`            | Public URL of the server                               |
| `SESSION_SECRET`      | Secret for session encryption                          |
| `AUTH0_DOMAIN`        | Auth0 tenant domain (if using Auth0)                   |
| `AUTH0_CLIENT_ID`     | Auth0 client ID (if using Auth0)                       |
| `AUTH0_CLIENT_SECRET` | Auth0 client secret (if using Auth0)                   |
| `CLERK_DOMAIN`        | Clerk domain (if using Clerk)                          |
| `CLERK_CLIENT_ID`     | Clerk client ID (if using Clerk)                       |
| `CLERK_CLIENT_SECRET` | Clerk client secret (if using Clerk)                   |
| `JWKS`                | JSON Web Key Set for token signing (required for prod) |

## Endpoints

| Endpoint                                    | Description                  |
| ------------------------------------------- | ---------------------------- |
| `POST /mcp`                                 | MCP endpoint (requires auth) |
| `GET /authorize`                            | Authorization endpoint       |
| `POST /token`                               | Token endpoint               |
| `POST /register`                            | Dynamic Client Registration  |
| `GET /jwks`                                 | JSON Web Key Set             |
| `GET /.well-known/openid-configuration`     | OIDC Discovery               |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata  |
| `GET /oauth/callback`                       | IdP callback handler         |
| `GET /health`                               | Health check                 |

## Production

For production deployments, generate and persist signing keys:

```bash
node -e "import('mcp-oidc-provider').then(m => m.generateJwks()).then(j => console.log(JSON.stringify(j)))"
```

Set the output as the `JWKS` environment variable. This ensures:

- Tokens remain valid across server restarts
- Multiple server instances can verify each other's tokens

## Testing

Use the MCP Inspector to test the server:

```bash
npx @modelcontextprotocol/inspector
```

Connect to `http://localhost:3000/mcp`, authenticate, then use the `whoami` tool to verify your user information.
