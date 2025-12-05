import dotenv from 'dotenv';
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ClerkClient } from 'mcp-oidc-provider/clerk';
import { setupMcpExpress } from 'mcp-oidc-provider/express';

// Load environment variables
dotenv.config();

const PORT = process.env['PORT'] ? parseInt(process.env['PORT'], 10) : 3000;
const BASE_URL = process.env['BASE_URL'] ?? `http://localhost:${PORT}`;
const SECRET = process.env['SESSION_SECRET'] ?? 'dev-secret-change-me';

// Clerk configuration is required
if (
  !process.env['CLERK_DOMAIN'] ||
  !process.env['CLERK_CLIENT_ID'] ||
  !process.env['CLERK_CLIENT_SECRET']
) {
  console.error('Error: Clerk environment variables are required.');
  console.error('Set CLERK_DOMAIN, CLERK_CLIENT_ID, and CLERK_CLIENT_SECRET');
  process.exit(1);
}

// Create Keyv store with Tigris backend
const store = new Keyv({ store: new KeyvTigris() });

// Setup complete MCP server with one call!
const { app, handleMcpRequest } = setupMcpExpress({
  idpClient: new ClerkClient({
    domain: process.env['CLERK_DOMAIN'],
    clientId: process.env['CLERK_CLIENT_ID'],
    clientSecret: process.env['CLERK_CLIENT_SECRET'],
    redirectUri: `${BASE_URL}/oauth/callback`,
  }),
  store,
  baseUrl: BASE_URL,
  secret: SECRET,
  isProduction: process.env['NODE_ENV'] === 'production',
  // Clerk doesn't support offline_access scope
  idpScopes: 'openid email profile',
});

// Register MCP handler
// user is defined for POST (authenticated), undefined for GET/DELETE (stateless)
handleMcpRequest(async (req, res, user) => {
  const server = new McpServer(
    { name: 'example-clerk-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  // Register whoami tool
  server.registerTool(
    'whoami',
    { description: 'Get information about the currently authenticated user' },
    async () => ({
      content: [{ type: 'text', text: user ? JSON.stringify(user, null, 2) : 'Not authenticated' }],
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
  console.log(`Example Clerk MCP server running at ${BASE_URL}`);
  console.log(`MCP endpoint: ${BASE_URL}/mcp`);
});
