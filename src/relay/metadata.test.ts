import { describe, it, expect } from 'vitest';
import { RELAY_ROUTES, buildRelayMetadata } from './metadata.js';

describe('buildRelayMetadata', () => {
  it('describes the relay as an OAuth 2.1 authorization server', () => {
    const metadata = buildRelayMetadata({
      issuer: 'https://relay.example',
      scopesSupported: ['openid', 'email'],
      dynamicRegistration: true,
      clientIdMetadataDocuments: true,
    });

    expect(metadata).toEqual({
      issuer: 'https://relay.example',
      authorization_endpoint: `https://relay.example${RELAY_ROUTES.authorization}`,
      token_endpoint: `https://relay.example${RELAY_ROUTES.token}`,
      registration_endpoint: `https://relay.example${RELAY_ROUTES.registration}`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      scopes_supported: ['openid', 'email'],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    });
  });

  it('omits the registration endpoint when dynamic registration is off', () => {
    const metadata = buildRelayMetadata({
      issuer: 'https://relay.example',
      scopesSupported: [],
      dynamicRegistration: false,
      clientIdMetadataDocuments: false,
      serviceDocumentation: 'https://relay.example/docs',
    });

    expect(metadata.registration_endpoint).toBeUndefined();
    expect(metadata.client_id_metadata_document_supported).toBe(false);
    expect(metadata.service_documentation).toBe('https://relay.example/docs');
  });
});
