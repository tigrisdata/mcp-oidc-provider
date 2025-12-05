import dotenv from 'dotenv';
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { type JWKS } from 'mcp-oidc-provider';
import { setupMcpExpress } from 'mcp-oidc-provider/express';
import { getIdentityProviderClientFromEnv } from './idp.js';
import { getIdpTokens } from '../../../dist/mcp/index.js';

// Load environment variables
dotenv.config();

const PORT = process.env['PORT'] ? parseInt(process.env['PORT'], 10) : 3000;
const BASE_URL = process.env['BASE_URL'] ?? `http://localhost:${PORT}`;
const SECRET = process.env['SESSION_SECRET'] ?? 'dev-secret-change-me';

// Parse JWKS from environment variable if available
const jwks: JWKS | undefined = process.env['JWKS'] ? JSON.parse(process.env['JWKS']) : undefined;

// Create Keyv store with Tigris backend
const store = new Keyv({ store: new KeyvTigris() });

// Setup complete MCP server with one call!
const { app, handleMcpRequest } = setupMcpExpress({
  idpClient: getIdentityProviderClientFromEnv(BASE_URL),
  store,
  baseUrl: BASE_URL,
  secret: SECRET,
  jwks,
  isProduction: process.env['NODE_ENV'] === 'production',
});

// Register MCP handler
handleMcpRequest(async (req, res) => {
  // req.user is set by setupMcpExpress auth middleware
  // For POST requests, auth is enforced so req.user is always defined
  // For GET/DELETE requests (stateless), req.user is undefined
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const server = new McpServer(
    { name: 'example-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  // Register whoami tool
  server.registerTool(
    'whoami',
    { description: 'Get information about the currently authenticated user' },
    async () => {
      const idpTokens = getIdpTokens(req.user);
      return {
        content: [{ type: 'text', text: JSON.stringify({ user: req.user, idpTokens }, null, 2) }],
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
});

// Start server
app.listen(PORT, () => {
  console.log(`Example MCP server running at ${BASE_URL}`);
  console.log(`MCP endpoint: ${BASE_URL}/mcp`);
});
