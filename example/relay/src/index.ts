/**
 * An MCP server protected by mcp-oidc-provider's auth relay.
 *
 * One Express app on one origin serves:
 * - the OAuth endpoints MCP clients use (/.well-known/*, /register, /authorize, /token)
 * - the identity provider callback (/oauth/callback)
 * - the MCP endpoint (/mcp), which accepts the identity provider's access tokens
 */

import 'dotenv/config';
import { createMcpExpressApp, requireBearerAuth } from '@modelcontextprotocol/express';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { McpServer } from '@modelcontextprotocol/server';
import { Keyv } from 'keyv';
import { createAuthRelay } from 'mcp-oidc-provider';
import { z } from 'zod';

const required = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable ${name}`);
  return value;
};

const PORT = Number(process.env['PORT'] ?? 3000);
const BASE_URL = process.env['BASE_URL'] ?? `http://localhost:${PORT}`;

// Any Keyv adapter works (Redis, Postgres, Tigris, ...). The store holds client
// registrations and authorization requests in flight; never tokens.
const store = new Keyv();

const relay = createAuthRelay({
  baseUrl: BASE_URL,
  upstream: {
    issuer: required('OIDC_ISSUER'),
    clientId: required('OIDC_CLIENT_ID'),
    clientSecret: required('OIDC_CLIENT_SECRET'),
    audience: required('OIDC_AUDIENCE'),
  },
  store,
  resourceName: 'Example MCP server',
  // Application data for req.auth.extra.customData: here, the user's profile
  // from the identity provider's UserInfo endpoint (cached per token).
  customData: async ({ claims, userinfo }) => {
    const profile = await userinfo();
    return { email: profile['email'], name: profile['name'], scope: claims['scope'] };
  },
});

// Host header validation (DNS rebinding protection) and JSON body parsing from the MCP SDK
const app = createMcpExpressApp({
  host: '0.0.0.0',
  allowedHosts: [new URL(BASE_URL).hostname],
});

// OAuth endpoints, discovery documents and CORS for /mcp
app.use(relay.router);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

const mcpAuth = requireBearerAuth({
  verifier: relay.verifier,
  resourceMetadataUrl: relay.resourceMetadataUrl,
  expectedResource: relay.resource,
});

app.post('/mcp', mcpAuth, async (req, res) => {
  const auth = req.auth;
  const customData = auth?.extra?.['customData'] as { email?: string; name?: string } | undefined;

  const server = new McpServer({ name: 'example-mcp', version: '1.0.0' });
  server.registerTool(
    'whoami',
    {
      title: 'Who am I',
      description: 'Returns the identity the access token belongs to',
      inputSchema: {},
      outputSchema: {
        sub: z.string(),
        email: z.string().optional(),
        name: z.string().optional(),
        scopes: z.array(z.string()),
      },
    },
    async () => {
      const structuredContent = {
        sub: String(auth?.extra?.['sub'] ?? ''),
        email: customData?.email,
        name: customData?.name,
        scopes: auth?.scopes ?? [],
      };
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(structuredContent) }],
        structuredContent,
      };
    }
  );

  // Stateless: one transport per request
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
});

app.listen(PORT, () => {
  console.log(`MCP server:      ${BASE_URL}/mcp`);
  console.log(`Auth metadata:   ${BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`Resource data:   ${relay.resourceMetadataUrl}`);
});
