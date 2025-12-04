/**
 * Standalone OIDC Server Example
 *
 * This example shows how to run the OIDC provider as a standalone server
 * and use the MCP SDK's ProxyOAuthServerProvider + mcpAuthRouter to proxy OAuth to it.
 *
 * Architecture:
 * - OIDC Server (port 4001): Handles OAuth/OIDC, DCR, token issuance
 * - MCP Server (port 3001): Your MCP server using SDK's auth proxy
 */

import dotenv from 'dotenv';
import express, { type Request, type Response } from 'express';
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';

import { createOidcServer } from 'mcp-oidc-provider/express';
import { Auth0Client } from 'mcp-oidc-provider/auth0';
import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';

dotenv.config();

const OIDC_PORT = process.env['OIDC_PORT'] ? parseInt(process.env['OIDC_PORT'], 10) : 4001;
const MCP_PORT = process.env['MCP_PORT'] ? parseInt(process.env['MCP_PORT'], 10) : 3001;
const OIDC_BASE_URL = process.env['OIDC_BASE_URL'] ?? `http://localhost:${OIDC_PORT}`;
const MCP_BASE_URL = process.env['MCP_BASE_URL'] ?? `http://localhost:${MCP_PORT}`;
const SECRET = process.env['SESSION_SECRET'] ?? 'dev-secret-change-me';

// Validate Auth0 config
if (
  !process.env['AUTH0_DOMAIN'] ||
  !process.env['AUTH0_CLIENT_ID'] ||
  !process.env['AUTH0_CLIENT_SECRET']
) {
  console.error('Error: Auth0 environment variables are required.');
  console.error('Set AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET');
  process.exit(1);
}

// Create Keyv store with Tigris backend
const store = new Keyv({ store: new KeyvTigris() });

// ============================================
// 1. Start Standalone OIDC Server (port 4001)
// ============================================
const oidcServer = createOidcServer({
  idpClient: new Auth0Client({
    domain: process.env['AUTH0_DOMAIN'],
    clientId: process.env['AUTH0_CLIENT_ID'],
    clientSecret: process.env['AUTH0_CLIENT_SECRET'],
    redirectUri: `${OIDC_BASE_URL}/oauth/callback`,
    audience: process.env['AUTH0_AUDIENCE'],
  }),
  store,
  secret: SECRET,
  port: OIDC_PORT,
  baseUrl: OIDC_BASE_URL,
  isProduction: process.env['NODE_ENV'] === 'production',
  onListen: (_port, baseUrl) => {
    console.log(`OIDC Server running at ${baseUrl}`);
    console.log(`  Authorization: ${baseUrl}/authorize`);
    console.log(`  Token: ${baseUrl}/token`);
    console.log(`  Registration: ${baseUrl}/register`);
    console.log(`  JWKS: ${baseUrl}/jwks`);
  },
});

await oidcServer.start();

// ============================================
// 2. Start MCP Server with SDK Auth (port 3001)
// ============================================
const mcpApp = express();
mcpApp.set('trust proxy', 1);

// Create MCP auth provider - provides config for ProxyOAuthServerProvider + routes
// The routes include CORS, health check, and protected resource metadata (RFC 9728)
const { proxyOAuthServerProviderConfig, mcpRoutes, resourceMetadataUrl } = createMcpAuthProvider({
  oidcServer,
  store,
  mcpServerBaseUrl: MCP_BASE_URL,
});

// Create ProxyOAuthServerProvider directly with the config
const authProvider = new ProxyOAuthServerProvider(proxyOAuthServerProviderConfig);

// Mount the routes (includes CORS, /health, and /.well-known/oauth-protected-resource)
mcpApp.use(mcpRoutes);

// Install MCP auth router at the root (handles OAuth endpoints)
mcpApp.use(
  mcpAuthRouter({
    provider: authProvider,
    issuerUrl: new URL(OIDC_BASE_URL),
    baseUrl: new URL(MCP_BASE_URL),
    resourceServerUrl: new URL(`${MCP_BASE_URL}/mcp`),
    scopesSupported: ['openid', 'email', 'profile', 'offline_access'],
    serviceDocumentationUrl: new URL('https://github.com/tigrisdata/mcp-oidc-provider'),
  })
);

// Body parser for MCP endpoint
mcpApp.use(express.json());

// MCP endpoint with bearer auth middleware
mcpApp.post(
  '/mcp',
  requireBearerAuth({
    verifier: authProvider,
    resourceMetadataUrl,
  }),
  async (req: Request, res: Response) => {
    // Get auth info from the request (set by requireBearerAuth middleware)
    const authInfo = req.auth;

    if (!authInfo) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Create MCP server with whoami tool
    const server = new McpServer(
      { name: 'standalone-mcp-server', version: '1.0.0' },
      { capabilities: { tools: {} } }
    );

    // Register whoami tool that returns user info from session claims
    server.registerTool(
      'whoami',
      { description: 'Get current user info from session' },
      async () => {
        const tokenResult = await oidcServer.validateToken(authInfo.token);

        if (!tokenResult.valid || !tokenResult.user) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  { error: 'Invalid token', message: tokenResult.error },
                  null,
                  2
                ),
              },
            ],
          };
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ tokenResult }, null, 2),
            },
          ],
        };
      }
    );

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on('close', () => {
      void transport.close();
      void server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  }
);

// Error handler - catch all unhandled errors (must have 4 params for Express to recognize it)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
mcpApp.use((err: Error, _req: Request, res: Response, _next: () => void) => {
  console.error('Express Error:', err.message);
  res.status(500).json({ error: 'server_error', error_description: err.message });
});

// 404 handler
mcpApp.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not Found' });
});

mcpApp.listen(MCP_PORT, () => {
  console.log('');
  console.log(`MCP Server running at ${MCP_BASE_URL}`);
  console.log(`  MCP endpoint: ${MCP_BASE_URL}/mcp`);
  console.log(`  OAuth metadata: ${MCP_BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`  Protected resource: ${resourceMetadataUrl}`);
});
