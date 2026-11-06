# Example: MCP server with the auth relay

A single Express app that serves an MCP endpoint and, on the same origin, the OAuth endpoints MCP clients need. Users sign in at your identity provider; the relay never mints tokens.

## Setup

1. Register a confidential web application at your identity provider with `http://localhost:3000/oauth/callback` as the callback URL. Make sure it may request refresh tokens (`offline_access`) and that an API / audience exists so the provider issues JWT access tokens.
2. Copy `.env.example` to `.env` and fill in the issuer, client ID, client secret and audience.
3. Install and run:

```bash
npm install
npm run dev
```

## Try it

With the [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npx @modelcontextprotocol/inspector
```

Connect to `http://localhost:3000/mcp` with transport "Streamable HTTP". The Inspector discovers the relay through the `401` challenge, registers itself, shows you the relay's consent page, sends you to your identity provider and comes back with a token. Call the `whoami` tool to see the identity behind the token.

## Endpoints

| Path | Purpose |
| --- | --- |
| `POST /mcp` | MCP endpoint (bearer token required) |
| `/.well-known/oauth-protected-resource/mcp` | Protected resource metadata (RFC 9728) |
| `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `POST /register` | Dynamic Client Registration (RFC 7591) |
| `GET /authorize`, `POST /authorize/consent` | Authorization endpoint and consent decision |
| `GET /oauth/callback` | Where the identity provider redirects back to |
| `POST /token` | Token endpoint (authorization code and refresh token grants) |
| `GET /health` | Health check |
