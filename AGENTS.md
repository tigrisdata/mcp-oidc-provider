Project Instructions for mcp-oidc-provider

## Overview

This is `mcp-oidc-provider` - an Express middleware that acts as an OIDC provider for MCP (Model Context Protocol) servers with support for any OIDC-compliant identity provider as its backend.

## Key Concepts

- **OIDC Provider**: Acts as a man-in-the-middle between MCP clients and upstream identity providers
- **Deployment**: The OIDC server is its own Express app (`createOidcServer`). The MCP server is an OAuth resource server built with the MCP TypeScript SDK v2: `requireBearerAuth` from `@modelcontextprotocol/express` with the verifier and metadata routes from `createMcpAuthProvider`
- **Storage**: Uses Keyv for abstraction - supports any Keyv-compatible backend (Tigris, Redis, in-memory)

## Project Structure

- `src/oidc/` - Core OIDC server implementation (`createOidcServer`, `OidcClient`)
- `src/mcp/` - MCP resource server side (`createMcpAuthProvider`, `getIdpTokens`)
- `src/core/` - Core provider implementation
- `src/utils/` - Utilities (JWKS generation, etc.)
- `example/` - Example implementations

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

- Tests are written with Vitest
- Coverage is tracked via Codecov
- Run `npm run test:coverage` before submitting PRs

## Commit Messages and Releases

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) style by convention (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`). This is not enforced by tooling.

Releases are driven by [changesets](https://github.com/changesets/changesets), not by commit messages:

- Every PR that changes published behaviour must add a changeset: `npx changeset`, pick the bump type (`patch`, `minor`, `major`) and describe the change for the changelog.
- On merge to `main`, the release workflow opens or updates a "Version Packages" PR that applies pending changesets to `package.json` and `CHANGELOG.md`.
- Merging the "Version Packages" PR publishes to npm via trusted publishing (no npm token).

## Important Notes

- JWKS keys are auto-generated in development but must be persisted for production
- Versioning and publishing are handled by changesets (see above)
- Husky runs pre-commit hooks for linting and formatting

## Related Links

- Repository: https://github.com/tigrisdata/mcp-oidc-provider
- Issues: https://github.com/tigrisdata/mcp-oidc-provider/issues
- NPM: https://www.npmjs.com/package/mcp-oidc-provider
