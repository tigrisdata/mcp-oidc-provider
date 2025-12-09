#!/usr/bin/env node
import { generateJwks } from '../utils/jwks.js';

async function main() {
  const args = process.argv.slice(2);

  // Parse arguments
  let pretty = false;
  let help = false;

  for (const arg of args) {
    if (arg === '--pretty' || arg === '-p') {
      pretty = true;
    } else if (arg === '--help' || arg === '-h') {
      help = true;
    }
  }

  if (help) {
    console.log(`
mcp-oidc-generate-jwks - Generate JWKS for mcp-oidc-provider

Usage:
  npx mcp-oidc-generate-jwks [options]

Options:
  -p, --pretty    Pretty print the JSON output
  -h, --help      Show this help message

Example:
  npx mcp-oidc-generate-jwks > jwks.json
  npx mcp-oidc-generate-jwks --pretty
  JWKS=$(npx mcp-oidc-generate-jwks)

The generated JWKS should be stored securely and provided to your
OIDC server via the 'jwks' option or JWKS environment variable.
`);
    process.exit(0);
  }

  try {
    const jwks = await generateJwks();
    const output = pretty ? JSON.stringify(jwks, null, 2) : JSON.stringify(jwks);
    console.log(output);
  } catch (error) {
    console.error('Failed to generate JWKS:', error);
    process.exit(1);
  }
}

main();
