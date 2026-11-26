# mcp-oidc-provider

## 2.1.3

### Patch Changes

- [#53](https://github.com/tigrisdata/mcp-oidc-provider/pull/53) [`603a1ee`](https://github.com/tigrisdata/mcp-oidc-provider/commit/603a1ee0e4dc2876adcb31d8b11de96ec9f6351f) Thanks [@designcode](https://github.com/designcode)! - Mark the package as archived and no longer maintained. The README now explains why and links to [You don't need to make your own OIDC server anymore](https://www.tigrisdata.com/blog/you-dont-need-make-oidc-server/).

- [#46](https://github.com/tigrisdata/mcp-oidc-provider/pull/46) [`2627188`](https://github.com/tigrisdata/mcp-oidc-provider/commit/2627188cb0045dc84293629e2ff1e7110545b2e6) Thanks [@designcode](https://github.com/designcode)! - `openid-client` is now a regular dependency instead of an optional one. `OidcClient` imports it unconditionally and is re-exported from the package root, so installing without it broke `import 'mcp-oidc-provider'`. You no longer need to install `openid-client` yourself.
