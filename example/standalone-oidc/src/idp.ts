import { OidcClient } from 'mcp-oidc-provider/oidc';

export function getIdentityProviderClientFromEnv(baseUrl: string): OidcClient {
  // Generic OIDC provider (works with any OIDC-compliant provider)
  if (process.env['OIDC_ISSUER'] && process.env['OIDC_CLIENT_ID'] && process.env['OIDC_CLIENT_SECRET']) {
    return new OidcClient({
      issuer: process.env['OIDC_ISSUER'],
      clientId: process.env['OIDC_CLIENT_ID'],
      clientSecret: process.env['OIDC_CLIENT_SECRET'],
      redirectUri: `${baseUrl}/oauth/callback`,
      scopes: process.env['OIDC_SCOPES'],
    });
  }

  // Auth0 (convenience - uses OIDC_* vars with Auth0 defaults)
  if (
    process.env['AUTH0_DOMAIN'] &&
    process.env['AUTH0_CLIENT_ID'] &&
    process.env['AUTH0_CLIENT_SECRET']
  ) {
    return new OidcClient({
      issuer: `https://${process.env['AUTH0_DOMAIN']}`,
      clientId: process.env['AUTH0_CLIENT_ID'],
      clientSecret: process.env['AUTH0_CLIENT_SECRET'],
      redirectUri: `${baseUrl}/oauth/callback`,
      scopes: 'openid email profile offline_access',
      additionalAuthParams: process.env['AUTH0_AUDIENCE']
        ? { audience: process.env['AUTH0_AUDIENCE'] }
        : undefined,
    });
  }

  // Clerk (convenience - uses CLERK_* vars with Clerk defaults)
  if (
    process.env['CLERK_DOMAIN'] &&
    process.env['CLERK_CLIENT_ID'] &&
    process.env['CLERK_CLIENT_SECRET']
  ) {
    return new OidcClient({
      issuer: process.env['CLERK_DOMAIN'].startsWith('http')
        ? process.env['CLERK_DOMAIN']
        : `https://${process.env['CLERK_DOMAIN']}`,
      clientId: process.env['CLERK_CLIENT_ID'],
      clientSecret: process.env['CLERK_CLIENT_SECRET'],
      redirectUri: `${baseUrl}/oauth/callback`,
      // Clerk doesn't support offline_access
      scopes: 'openid email profile',
      // Extract Clerk-specific organization data
      extractCustomData: (claims) => {
        const customData: Record<string, unknown> = {};
        if (claims['org_id']) {
          customData['organization'] = {
            id: claims['org_id'],
            slug: claims['org_slug'],
            role: claims['org_role'],
            permissions: claims['org_permissions'],
          };
        }
        if (claims['public_metadata']) {
          customData['publicMetadata'] = claims['public_metadata'];
        }
        if (claims['unsafe_metadata']) {
          customData['unsafeMetadata'] = claims['unsafe_metadata'];
        }
        return Object.keys(customData).length > 0 ? customData : undefined;
      },
    });
  }

  throw new Error(
    'Identity provider not configured. Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET ' +
      '(or AUTH0_* or CLERK_* environment variables)'
  );
}
