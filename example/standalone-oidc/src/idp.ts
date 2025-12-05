import { Auth0Client } from 'mcp-oidc-provider/auth0';
import { IdentityProviderClient } from 'mcp-oidc-provider';
import { ClerkClient } from 'mcp-oidc-provider/clerk';

export function getIdentityProviderClientFromEnv(baseUrl: string): IdentityProviderClient {
  if (
    process.env['AUTH0_DOMAIN'] &&
    process.env['AUTH0_CLIENT_ID'] &&
    process.env['AUTH0_CLIENT_SECRET']
  ) {
    return new Auth0Client({
      domain: process.env['AUTH0_DOMAIN'],
      clientId: process.env['AUTH0_CLIENT_ID'],
      clientSecret: process.env['AUTH0_CLIENT_SECRET'],
      redirectUri: `${baseUrl}/oauth/callback`,
      audience: process.env['AUTH0_AUDIENCE'],
    });
  }

  if (
    process.env['CLERK_DOMAIN'] &&
    process.env['CLERK_CLIENT_ID'] &&
    process.env['CLERK_CLIENT_SECRET']
  ) {
    return new ClerkClient({
      domain: process.env['CLERK_DOMAIN'],
      clientId: process.env['CLERK_CLIENT_ID'],
      clientSecret: process.env['CLERK_CLIENT_SECRET'],
      redirectUri: `${baseUrl}/oauth/callback`,
    });
  }

  throw new Error('Identity provider client not found');
}
