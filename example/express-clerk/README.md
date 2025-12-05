# MCP OIDC Provider Example with Clerk

A minimal MCP server example using `mcp-oidc-provider` with Clerk authentication.

## Features

- Express.js server with OAuth 2.0/OIDC authentication
- Clerk as the identity provider
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

3. Configure your Clerk application:
   - Go to the [Clerk Dashboard](https://dashboard.clerk.com)
   - Create a new application or select an existing one
   - Go to **Configure** > **SSO Connections** or use the built-in OIDC support
   - Copy the domain, client ID, and client secret to `.env`
   - Set the callback URL to `http://localhost:3000/oauth/callback` in your Clerk settings

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
| `CLERK_DOMAIN` | Your Clerk domain (e.g., `your-app.clerk.accounts.dev`) |
| `CLERK_CLIENT_ID` | Clerk OAuth client ID |
| `CLERK_CLIENT_SECRET` | Clerk OAuth client secret |
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

After authenticating with Clerk, you can use the `whoami` tool to see your user information, including Clerk-specific claims like organization data.

## Clerk-specific Features

The Clerk client extracts additional user data from the ID token:

- `firstName`, `lastName`, `username` - Basic profile info
- `organization` - Organization ID, slug, role, and permissions (if using Clerk Organizations)
- `publicMetadata` - Any public metadata set on the user
