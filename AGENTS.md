Project Instructions for mcp-oidc-provider

## Overview

This is `mcp-oidc-provider` - an Express middleware that acts as an OIDC provider for MCP (Model Context Protocol) servers with support for any OIDC-compliant identity provider as its backend.

## Key Concepts

- **OIDC Provider**: Acts as a man-in-the-middle between MCP clients and upstream identity providers
- **Two Deployment Modes**:
  - **Standalone**: Separate OIDC server, MCP server proxies auth requests to it
  - **Integrated**: Single Express app hosting both OIDC and MCP
- **Storage**: Uses Keyv for abstraction - supports any Keyv-compatible backend (Tigris, Redis, in-memory)

## Project Structure

- `src/oidc/` - Core OIDC server implementation (`createOidcServer`, `OidcClient`)
- `src/mcp/` - MCP-specific utilities (`setupMcpExpress`, `createMcpAuthProvider`)
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

## Commit Messages

Must follow [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Example: `feat: add support for custom OIDC client implementations`

## Important Notes

- JWKS keys are auto-generated in development but must be persisted for production
- The package uses semantic-release for automated versioning
- Commitlint enforces conventional commit format
- Husky runs pre-commit hooks for linting and formatting

## Related Links

- Repository: https://github.com/tigrisdata/mcp-oidc-provider
- Issues: https://github.com/tigrisdata/mcp-oidc-provider/issues
- NPM: https://www.npmjs.com/package/mcp-oidc-provider
