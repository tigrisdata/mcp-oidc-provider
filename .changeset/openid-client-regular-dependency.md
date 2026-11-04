---
'mcp-oidc-provider': patch
---

`openid-client` is now a regular dependency instead of an optional one. `OidcClient` imports it unconditionally and is re-exported from the package root, so installing without it broke `import 'mcp-oidc-provider'`. You no longer need to install `openid-client` yourself.
