Project Instructions for mcp-oidc-provider

## Overview

`mcp-oidc-provider` is an OAuth 2.1 authorization server for MCP (Model Context Protocol) servers that relays to an upstream OpenID Connect identity provider (Auth0, Okta, Keycloak, Entra ID, ...). It gives MCP clients what the MCP authorization spec requires (protected resource metadata, authorization server metadata, Dynamic Client Registration, Client ID Metadata Documents, PKCE, a consent page) while every token is minted by the identity provider. The relay stores no tokens and holds no signing key.

## Key Concepts

- **Relay, not provider**: `/authorize` validates the MCP client and redirects to the identity provider with the client's PKCE challenge; the callback hands a relay code to the client; `/token` exchanges it at the identity provider with the relay's single confidential client and returns the provider's response as is.
- **One Express router**: `createAuthRelay` returns `router` (mount at the root of the MCP app), `verifier` (for the MCP SDK's `requireBearerAuth`), `resource` and `resourceMetadataUrl`.
- **Verification**: the MCP endpoint verifies the provider's JWT access tokens against its JWKS: issuer, `upstream.audience`, expiry. `customData` derives application data from claims or a cached UserInfo lookup.
- **Storage**: Keyv (any adapter) holds client registrations, cached client metadata documents and in-flight authorization requests only.
- **Consent**: the relay asks the user to approve each client and redirect URI (confused-deputy mitigation from the MCP spec). Decisions live in a signed cookie.

## Project Structure

- `src/relay/create-auth-relay.ts` - composes the router, verifier and metadata
- `src/relay/authorize.ts` - `/authorize`, consent decision, identity provider callback
- `src/relay/token.ts` - `/token`
- `src/relay/clients.ts` - Dynamic Client Registration, Client ID Metadata Documents, redirect URI policy, client authentication
- `src/relay/upstream.ts` - identity provider discovery, token endpoint, UserInfo, JWKS
- `src/relay/verifier.ts` - `OAuthTokenVerifier` for the MCP SDK
- `src/relay/consent.ts`, `src/relay/html.ts` - consent cookie and pages
- `src/express/cors.ts` - CORS for the MCP endpoint
- `src/test/helpers/upstream.ts` - fake identity provider used by the tests
- `example/relay/` - runnable example

## Development Commands

```bash
npm run build          # Build the project
npm run dev            # Watch mode for development
npm run lint           # Lint TypeScript code
npm run lint:fix       # Auto-fix lint issues
npm run format         # Format code with Prettier
npm run format:check   # Check formatting
npm run type-check     # Type check without emitting
npm test               # Run tests
npm run test:watch     # Watch mode for tests
npm run test:coverage  # Run tests with coverage
```

## Code Style

- Use ESLint and Prettier configurations in the project
- Follow TypeScript best practices
- Run `npm run lint:fix` and `npm run format` before committing

## Testing

- Tests are written with Vitest; HTTP behaviour is tested against real listeners (`listen()` helper + `fetch`) and a fake identity provider (`startFakeUpstream()`)
- Coverage thresholds are enforced (see `vitest.config.ts`); run `npm run test:coverage` before submitting PRs

## Commit Messages and Releases

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) style by convention (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`). This is not enforced by tooling.

Releases are driven by [changesets](https://github.com/changesets/changesets), not by commit messages:

- Every PR that changes published behaviour must add a changeset: `npx changeset`, pick the bump type (`patch`, `minor`, `major`) and describe the change for the changelog.
- On merge to `main`, the release workflow opens or updates a "Version Packages" PR that applies pending changesets to `package.json` and `CHANGELOG.md`.
- Merging the "Version Packages" PR publishes to npm via trusted publishing (no npm token).

## Important Notes

- The relay must be reachable at `baseUrl` over HTTPS in production; the MCP SDK rejects a non-HTTPS issuer other than `localhost` unless `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true` is set
- The identity provider must issue JWT access tokens for `upstream.audience`
- Keep the package generic: nothing in code or docs may assume one particular deployment or identity provider
- Versioning and publishing are handled by changesets (see above)
- Husky runs pre-commit hooks for linting and formatting

## Related Links

- Repository: https://github.com/tigrisdata/mcp-oidc-provider
- Issues: https://github.com/tigrisdata/mcp-oidc-provider/issues
- NPM: https://www.npmjs.com/package/mcp-oidc-provider
