# MCP OIDC Provider Example

A minimal MCP server example using `mcp-oidc-provider` with Auth0 authentication.

## Features

- Express.js server with OAuth 2.0/OIDC authentication
- Auth0 as the identity provider
- Single MCP tool: `whoami` - returns authenticated user information

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
   - Set the callback URL to `http://localhost:3000/oauth/callback`
   - Copy the domain, client ID, and client secret to `.env`

4. Run the development server:

```bash
npm run dev
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default: 3000) |
| `BASE_URL` | Public URL of the server |
| `SESSION_SECRET` | Secret for session encryption |
| `AUTH0_DOMAIN` | Your Auth0 tenant domain |
| `AUTH0_CLIENT_ID` | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret |
| `AUTH0_AUDIENCE` | Optional API audience |
| `JWKS` | JSON Web Key Set for token signing (required for production) |

## Production Setup

For production deployments, you need to generate and persist signing keys:

```bash
# Generate JWKS (run once, save the output securely)
node -e "import('mcp-oidc-provider').then(m => m.generateJwks()).then(j => console.log(JSON.stringify(j)))"
```

Set the output as the `JWKS` environment variable in your production environment. This ensures:
- Tokens remain valid across server restarts
- Multiple server instances can verify each other's tokens

## Usage

Once running, the server exposes:

- `GET /health` - Health check endpoint
- `POST /mcp` - MCP endpoint (requires authentication)
- `GET /.well-known/oauth-protected-resource` - OAuth resource metadata
- Standard OIDC endpoints (`/authorize`, `/token`, `/jwks`, etc.)

### Testing with an MCP Client

Configure your MCP client (Cursor, VS Code, etc.) to connect to:

```
http://localhost:3000/mcp
```

After authenticating, you can use the `whoami` tool to see your user information.
