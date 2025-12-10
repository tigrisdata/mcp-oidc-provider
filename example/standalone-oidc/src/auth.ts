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
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';

import { createOidcServer } from 'mcp-oidc-provider/express';
import { getIdentityProviderClientFromEnv } from './idp.js';
import { type JWKS } from 'mcp-oidc-provider';

dotenv.config();

const OIDC_PORT = process.env['OIDC_PORT'] ? parseInt(process.env['OIDC_PORT'], 10) : 4001;
const OIDC_BASE_URL = process.env['OIDC_BASE_URL'] ?? `http://localhost:${OIDC_PORT}`;
const SECRET = process.env['SESSION_SECRET'] ?? 'dev-secret-change-me';

// Parse JWKS from environment variable if available
const jwks: JWKS | undefined = process.env['JWKS'] ? JSON.parse(process.env['JWKS']) : undefined;

// Create Keyv store with Tigris backend
const store = new Keyv({ store: new KeyvTigris() });

// ============================================
// 1. Start Standalone OIDC Server (port 4001)
// ============================================
const oidcServer = createOidcServer({
  idpClient: getIdentityProviderClientFromEnv(OIDC_BASE_URL),
  store,
  secret: SECRET,
  baseUrl: OIDC_BASE_URL,
  port: OIDC_PORT,
  isProduction: process.env['NODE_ENV'] === 'production',
  jwks,
  onListen: (baseUrl) => {
    console.log(`OIDC Server running at ${baseUrl}`);
    console.log(`  Authorization: ${baseUrl}/authorize`);
    console.log(`  Token: ${baseUrl}/token`);
    console.log(`  Registration: ${baseUrl}/register`);
    console.log(`  JWKS: ${baseUrl}/jwks`);
  },
});

await oidcServer.start();
