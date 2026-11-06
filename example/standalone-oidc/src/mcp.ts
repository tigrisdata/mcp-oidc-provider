/**
 * Standalone OIDC Server Example - MCP server
 *
 * The OIDC provider runs as a separate server (auth.ts). This MCP server is a
 * plain OAuth resource server built with the MCP SDK v2: it advertises the OIDC
 * server through protected resource metadata and verifies the bearer tokens the
 * OIDC server issued with `requireBearerAuth`.
 *
 * Architecture:
 * - OIDC Server (port 4001): Handles OAuth/OIDC, DCR, token issuance
 * - MCP Server (port 3001): Your MCP server, verifies tokens from the OIDC server
 */

import dotenv from 'dotenv';
import { setTimeout as sleep } from 'node:timers/promises';
import type { Request, Response } from 'express';
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { McpServer, type AuthInfo } from '@modelcontextprotocol/server';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { createMcpExpressApp, requireBearerAuth } from '@modelcontextprotocol/express';
import { createMcpAuthProvider, getIdpTokens } from 'mcp-oidc-provider/mcp';

dotenv.config();

const OIDC_PORT = process.env['OIDC_PORT'] ? parseInt(process.env['OIDC_PORT'], 10) : 4001;
const OIDC_BASE_URL = process.env['OIDC_BASE_URL'] ?? `http://localhost:${OIDC_PORT}`;
const MCP_PORT = process.env['MCP_PORT'] ? parseInt(process.env['MCP_PORT'], 10) : 3001;
const MCP_BASE_URL = process.env['MCP_BASE_URL'] ?? `http://localhost:${MCP_PORT}`;

// Same persistent store as the OIDC server (user sessions are looked up by the verifier)
const store = new Keyv({ store: new KeyvTigris() });

// ============================================
// 2. Start MCP Server (port 3001)
// ============================================

// Token verifier for the MCP SDK plus the OAuth metadata routes:
// /.well-known/oauth-protected-resource/mcp, the OIDC server's
// /.well-known/oauth-authorization-server (fetched once here) and CORS for /mcp.
// Both servers start together in this example, so wait for the OIDC server.
async function createAuthProvider() {
  for (let attempt = 1; ; attempt++) {
    try {
      return await createMcpAuthProvider({
        oidcBaseUrl: OIDC_BASE_URL,
        store,
        mcpServerBaseUrl: MCP_BASE_URL,
      });
    } catch (error) {
      if (attempt >= 30) throw error;
      console.log(`Waiting for the OIDC server at ${OIDC_BASE_URL}...`);
      await sleep(1000);
    }
  }
}

const { verifier, mcpRoutes, resourceMetadataUrl } = await createAuthProvider();

// Express app from the MCP SDK: JSON body parsing plus DNS rebinding protection.
// List every hostname this server is reached by.
const mcpApp = createMcpExpressApp({
  host: '0.0.0.0',
  allowedHosts: [new URL(MCP_BASE_URL).hostname],
});
mcpApp.set('trust proxy', 1);

mcpApp.use(mcpRoutes);

mcpApp.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// MCP endpoint with bearer auth middleware from the MCP SDK
mcpApp.post(
  '/mcp',
  requireBearerAuth({
    verifier,
    resourceMetadataUrl,
    // Only accept tokens issued for this MCP server (RFC 8707 audience binding)
    expectedResource: new URL(`${MCP_BASE_URL}/mcp`),
  }),
  async (req: Request, res: Response) => {
    // Auth info from the request (set by requireBearerAuth middleware)
    const authInfo = (req as Request & { auth?: AuthInfo }).auth;

    if (!authInfo) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Create MCP server with whoami tool
    const server = new McpServer({ name: 'standalone-mcp-server', version: '1.0.0' });

    // Register whoami tool that returns user info from session claims
    server.registerTool(
      'whoami',
      { description: 'Get current user info from session' },
      async () => {
        const idpTokens = getIdpTokens(authInfo);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ authInfo, idpTokens }, null, 2),
            },
          ],
        };
      }
    );

    const transport = new NodeStreamableHTTPServerTransport({
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
  console.log(`  Protected resource metadata: ${resourceMetadataUrl}`);
  console.log(`  Authorization server metadata: ${MCP_BASE_URL}/.well-known/oauth-authorization-server`);
});
