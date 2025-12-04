import dotenv from 'dotenv';
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import { type JWKS } from 'mcp-oidc-provider';
import { Auth0Client } from 'mcp-oidc-provider/auth0';
import { setupMcpExpress } from 'mcp-oidc-provider/express';

// Load environment variables
dotenv.config();

const PORT = process.env['PORT'] ? parseInt(process.env['PORT'], 10) : 3000;
const BASE_URL = process.env['BASE_URL'] ?? `http://localhost:${PORT}`;
const SECRET = process.env['SESSION_SECRET'] ?? 'dev-secret-change-me';

// Auth0 configuration is required
if (
  !process.env['AUTH0_DOMAIN'] ||
  !process.env['AUTH0_CLIENT_ID'] ||
  !process.env['AUTH0_CLIENT_SECRET']
) {
  console.error('Error: Auth0 environment variables are required.');
  console.error('Set AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET');
  process.exit(1);
}

// Parse JWKS from environment variable if available
const jwks: JWKS | undefined = process.env['JWKS'] ? JSON.parse(process.env['JWKS']) : undefined;

// Create Keyv store with Tigris backend
const store = new Keyv({ store: new KeyvTigris() });

// Setup complete MCP server with one call!
const { app, handleMcpRequest } = setupMcpExpress({
  idpClient: new Auth0Client({
    domain: process.env['AUTH0_DOMAIN'],
    clientId: process.env['AUTH0_CLIENT_ID'],
    clientSecret: process.env['AUTH0_CLIENT_SECRET'],
    redirectUri: `${BASE_URL}/oauth/callback`,
    audience: process.env['AUTH0_AUDIENCE'],
  }),
  store,
  baseUrl: BASE_URL,
  secret: SECRET,
  jwks,
  isProduction: process.env['NODE_ENV'] === 'production',
});

// Register MCP handler
handleMcpRequest(async (req, res, user) => {
  const server = new McpServer(
    { name: 'example-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  // Register whoami tool
  server.registerTool(
    'whoami',
    { description: 'Get information about the currently authenticated user' },
    async () => ({
      content: [{ type: 'text', text: JSON.stringify(user, null, 2) }],
    })
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
});

// Start server
app.listen(PORT, () => {
  console.log(`Example MCP server running at ${BASE_URL}`);
  console.log(`MCP endpoint: ${BASE_URL}/mcp`);
});
