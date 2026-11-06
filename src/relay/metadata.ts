/**
 * Authorization server metadata (RFC 8414) published by the relay.
 * @internal
 */

import type { AuthMetadataOptions } from '@modelcontextprotocol/server';

/** The metadata document type the MCP SDK expects. */
export type OAuthMetadata = AuthMetadataOptions['oauthMetadata'];

export const RELAY_ROUTES = {
  authorization: '/authorize',
  consent: '/authorize/consent',
  token: '/token',
  registration: '/register',
} as const;

/** Client authentication methods the relay's token endpoint accepts. */
export const TOKEN_ENDPOINT_AUTH_METHODS = ['none', 'client_secret_basic', 'client_secret_post'];

/** Grant types the relay forwards. */
export const GRANT_TYPES = ['authorization_code', 'refresh_token'];

export interface RelayMetadataOptions {
  issuer: string;
  scopesSupported: string[];
  dynamicRegistration: boolean;
  clientIdMetadataDocuments: boolean;
  serviceDocumentation?: string;
}

/** Build the relay's authorization server metadata. */
export function buildRelayMetadata(options: RelayMetadataOptions): OAuthMetadata {
  const { issuer } = options;
  return {
    issuer,
    authorization_endpoint: `${issuer}${RELAY_ROUTES.authorization}`,
    token_endpoint: `${issuer}${RELAY_ROUTES.token}`,
    ...(options.dynamicRegistration
      ? { registration_endpoint: `${issuer}${RELAY_ROUTES.registration}` }
      : {}),
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: GRANT_TYPES,
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS,
    scopes_supported: options.scopesSupported,
    client_id_metadata_document_supported: options.clientIdMetadataDocuments,
    authorization_response_iss_parameter_supported: true,
    ...(options.serviceDocumentation
      ? { service_documentation: options.serviceDocumentation }
      : {}),
  };
}
