# Architecture

## What This Package Does

1. **Acts as OIDC Server** to MCP clients - issues tokens, handles DCR, provides JWKS
2. **Acts as OIDC Client** to upstream IdP - redirects users to Auth0/Clerk for actual authentication
3. **Stores IdP tokens** - so your MCP tools can call upstream APIs on behalf of the user
4. **Auto-refreshes tokens** - both OIDC tokens (for MCP clients) and IdP tokens (for API calls)
5. **Auto-grants consent** - because users already consented at the upstream IdP

---

## Modes

### Mode 1: Standalone OIDC Server

Run OIDC server separately from your MCP implementation. Useful if your MCP server is in Next.js, Python, or any non-Express stack.

```
┌────────────────────┐      ┌────────────────────┐
│  OIDC Server       │      │  MCP Server        │
│  (port 4001)       │      │  (port 3001)       │
│                    │      │                    │
│  createOidcServer  │◄────►│  Your MCP impl     │
│  from /oidc        │      │  (any stack)       │
└─────────┬──────────┘      └─────────┬──────────┘
          │                           │
          └───────────┬───────────────┘
                      ▼
          ┌──────────────────────┐
          │  Shared Keyv Store   │
          │  (Tigris, Redis)     │
          └──────────────────────┘
```

### Mode 2: Integrated

Run OIDC + MCP in a single Express app. Simpler setup for new projects.

```
┌─────────────────────────────────────┐
│  Single Express App (port 3000)     │
│                                     │
│  setupMcpExpress from /mcp          │
│                                     │
│  ┌───────────────┐ ┌─────────────┐  │
│  │ OIDC Routes   │ │ MCP Routes  │  │
│  │ /authorize    │ │ POST /mcp   │  │
│  │ /token        │ │             │  │
│  │ /jwks         │ │             │  │
│  └───────────────┘ └─────────────┘  │
└─────────────────────────────────────┘
```

---

## Data Storage

All data stored in Keyv (Tigris, Redis or in-memory for dev).

### UserSession (30-day TTL)

Created after successful IdP authentication. Contains everything needed for MCP requests.

```typescript
{
  userId: "auth0|user123",        // From IdP's 'sub' claim
  claims: {                       // User identity
    email: "user@example.com",
    name: "John Doe",
    picture: "https://..."
  },
  tokenSet: {                     // IdP tokens for API calls
    accessToken: "idp_access_token",
    idToken: "eyJ...",
    refreshToken: "idp_refresh_token",
    expiresAt: 1704067200000
  },
  customData: {                   // Provider-specific data
    organizations: [...],         // e.g., from Clerk
    groups: [...]                 // e.g., from Okta
  }
}
```

### InteractionSession (30-min TTL)

Temporary storage during OAuth flow. Deleted after successful auth.

```typescript
{
  interactionUid: "abc123",
  idpState: "csrf_protection",
  idpNonce: "replay_prevention",
  codeVerifier: "pkce_verifier"
}
```

### OIDC Data (managed by oidc-provider)

- `oidc:AccessToken:{id}` - Issued access tokens (15 min)
- `oidc:RefreshToken:{id}` - Refresh tokens (30 days)
- `oidc:Client:{id}` - Dynamically registered clients
- `oidc:Grant:{id}` - Consent records (14 days)

---

## Token Validation

When an MCP request comes in with a Bearer token:

```
1. Extract token from Authorization header
                    │
                    ▼
2. Verify JWT signature using JWKS
   (tokens are always JWTs signed with your keys)
                    │
                    ▼
3. Extract accountId from 'sub' claim
                    │
                    ▼
4. Load UserSession from store
                    │
                    ▼
5. Check IdP token expiry
   └── Expires within 60s? → Auto-refresh
                    │
                    ▼
6. Return AuthenticatedUser
   {
     accountId, userId, claims,
     tokenSet, customData
   }
```

---

## Automatic Token Refresh

Both token types are automatically refreshed:

### OIDC Tokens (for MCP clients)

MCP clients use refresh tokens to get new access tokens. Standard OAuth flow, handled by `oidc-provider`.

### IdP Tokens (for upstream APIs)

```
Token issued          60s before expiry        Token expires
     │                       │                      │
     ▼                       ▼                      ▼
─────┼───────────────────────┼──────────────────────┼─────
     │                       │                      │
     │   Normal use          │  Auto-refresh        │
     │                       │  (on next request)   │
```

When `validateToken()` runs and IdP tokens expire within 60 seconds:

1. Call `idpClient.refreshToken(refreshToken)`
2. Update UserSession with new tokens
3. Continue request with fresh tokens

---

## Complete User Journey

This section walks through the entire lifecycle - from a user running `claude mcp add` to successfully calling an MCP tool.

### Step 1: User Adds MCP Server in Claude Code

The user runs the CLI command to add your MCP server.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Terminal                                                           │
│                                                                     │
│  $ claude mcp add my-tigris-server https://mcp.myapp.com/mcp        │
│                                                                     │
│  Adding MCP server...                                               │
│  Authentication required. Opening browser...                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Step 2: Dynamic Client Registration (First Time Only)

Claude Code registers itself with your OIDC server. This happens once and is cached.

```
Claude Code                               Your MCP Server
  │                                             │
  │  GET /.well-known/oauth-authorization-server│
  │ ───────────────────────────────────────────►│
  │                                             │
  │  { registration_endpoint: "/register" }     │
  │ ◄───────────────────────────────────────────│
  │                                             │
  │  POST /register                             │
  │  {                                          │
  │    client_name: "Claude Code",              │
  │    redirect_uris: ["http://127.0.0.1:*/.."] │
  │  }                                          │
  │ ───────────────────────────────────────────►│
  │                                             │
  │                      ┌──────────────────────┤
  │                      │ Store in Keyv:       │
  │                      │                      │
  │                      │ Key: oidc:Client:xyz │
  │                      │ Value: {             │
  │                      │   client_id,         │
  │                      │   client_secret,     │
  │                      │   redirect_uris      │
  │                      │ }                    │
  │                      │ TTL: 14 days         │
  │                      └──────────────────────┤
  │                                             │
  │  { client_id: "xyz", client_secret: "..." } │
  │ ◄───────────────────────────────────────────│
```

### Step 3: Authorization Request

Claude Code opens a browser window to your authorization endpoint.

```
Claude Code                              Your MCP Server
  │                                            │
  │  Opens browser:                            │
  │  GET /authorize                            │
  │    ?client_id=xyz                          │
  │    &redirect_uri=http://127.0.0.1:9876/..  │
  │    &code_challenge=abc123                  │
  │    &state=random_state                     │
  │ ──────────────────────────────────────────►│
  │                                            │
  │                      ┌─────────────────────┤
  │                      │ Validate:           │
  │                      │ - client_id exists  │
  │                      │ - redirect_uri OK   │
  │                      │ - localhost allowed │
  │                      └─────────────────────┤
  │                                            │
  │                      ┌─────────────────────┤
  │                      │ Create OIDC         │
  │                      │ interaction session │
  │                      │ (internal to        │
  │                      │  oidc-provider)     │
  │                      │                     │
  │                      │ Set session cookie  │
  │                      │ (links browser to   │
  │                      │  this auth flow)    │
  │                      └─────────────────────┤
```

### Step 4: Redirect to Upstream IdP

Your MCP server redirects to Auth0/Clerk for actual authentication.

```
Your MCP Server                               Auth0/Clerk
  │                                               │
  │  Generate PKCE, state, nonce                  │
  │                                               │
  │  ┌────────────────────────────────────────────┤
  │  │ Store in Keyv:                             │
  │  │                                            │
  │  │ Key: interaction:{sessionId}               │
  │  │ Value: {                                   │
  │  │   interactionUid: "...",                   │
  │  │   idpState: "csrf_token",                  │
  │  │   idpNonce: "replay_nonce",                │
  │  │   codeVerifier: "pkce_verifier"            │
  │  │ }                                          │
  │  │ TTL: 10 minutes                            │
  │  └────────────────────────────────────────────┤
  │                                               │
  │  302 Redirect                                 │
  │  Location: https://auth0.com/authorize        │
  │    ?client_id=your_auth0_app                  │
  │    &redirect_uri=https://your-server/cb       │
  │    &scope=openid email profile offline_access │
  │    &state=csrf_token                          │
  │    &nonce=replay_nonce                        │
  │    &code_challenge=pkce_challenge             │
  │ ─────────────────────────────────────────────►│
```

### Step 5: User Authenticates at IdP

User sees Auth0/Clerk login page and enters credentials.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser (Auth0 Login Page)                                         │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                     Sign In                                 │    │
│  │                                                             │    │
│  │  Email:    [user@example.com        ]                       │    │
│  │  Password: [••••••••••              ]                       │    │
│  │                                                             │    │
│  │            [Continue]                                       │    │
│  │                                                             │    │
│  │  ─────────── or ───────────                                 │    │
│  │                                                             │    │
│  │  [Continue with Google]                                     │    │
│  │  [Continue with GitHub]                                     │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Step 6: IdP Callback - Exchange Code for Tokens

Auth0 redirects back to your MCP server with an authorization code.

```
Auth0                                       Your MCP Server
  │                                               │
  │  302 Redirect                                 │
  │  Location: /oauth/callback?code=idp_code      │
  │ ─────────────────────────────────────────────►│
  │                                               │
  │                      ┌────────────────────────┤
  │                      │ Load InteractionSess   │
  │                      │ Verify state matches   │
  │                      └────────────────────────┤
  │                                               │
  │  POST https://auth0.com/oauth/token           │
  │  {                                            │
  │    code: "idp_code",                          │
  │    code_verifier: "pkce_verifier",            │
  │    redirect_uri: "..."                        │
  │  }                                            │
  │ ◄─────────────────────────────────────────────│
  │                                               │
  │  {                                            │
  │    access_token: "idp_access_token",          │
  │    id_token: "eyJ...",                        │
  │    refresh_token: "idp_refresh_token",        │
  │    expires_in: 86400                          │
  │  }                                            │
  │ ─────────────────────────────────────────────►│
  │                                               │
  │                      ┌────────────────────────┤
  │                      │ Store in Keyv:         │
  │                      │                        │
  │                      │ Key: session:{id}      │
  │                      │ Value: {               │
  │                      │   userId: "auth0|123", |
  │                      │   claims: {            │
  │                      │     email: "...",      │
  │                      │     name: "..."        │
  │                      │   },                   │
  │                      │   tokenSet: {          │
  │                      │     accessToken,       │
  │                      │     idToken,           │
  │                      │     refreshToken,      │
  │                      │     expiresAt          │
  │                      │   }                    │
  │                      │ }                      │
  │                      │ TTL: 30 days           │
  │                      └────────────────────────┤
  │                                               │
  │                      ┌────────────────────────┤
  │                      │ Delete:                │
  │                      │ interaction:{id}       │
  │                      │ (no longer needed)     │
  │                      └────────────────────────┤
```

### Step 7: Redirect Back to MCP Client with Code

Your MCP server redirects back to Claude Code's local callback server.

```
Your MCP Server                            Claude Code
  │                                            │
  │  302 Redirect                              │
  │  Location: http://127.0.0.1:9876/callback  │
  │    ?code=mcp_auth_code                     │
  │    &state=random_state                     │
  │ ──────────────────────────────────────────►│
  │                                            │
  │  (Browser closes, Claude Code receives code)
```

### Step 8: MCP Client Exchanges Code for Tokens

Claude Code exchanges the code for access and refresh tokens.

```
Claude Code                              Your MCP Server
  │                                            │
  │  POST /token                               │
  │  {                                         │
  │    grant_type: "authorization_code",       │
  │    code: "mcp_auth_code",                  │
  │    code_verifier: "original_verifier",     │
  │    client_id: "xyz",                       │
  │    client_secret: "..."                    │
  │  }                                         │
  │ ──────────────────────────────────────────►│
  │                                            │
  │                      ┌─────────────────────┤
  │                      │ Store in Keyv:      │
  │                      │                     │
  │                      │ oidc:AccessToken:{} │
  │                      │ TTL: 15 minutes     │
  │                      │                     │
  │                      │ oidc:RefreshToken:{}│
  │                      │ TTL: 30 days        │
  │                      │                     │
  │                      │ oidc:Grant:{}       │
  │                      │ TTL: 14 days        │
  │                      └─────────────────────┤
  │                                            │
  │  {                                         │
  │    access_token: "eyJhbG...",  ← JWT       │
  │    refresh_token: "refresh...",            │
  │    token_type: "Bearer",                   │
  │    expires_in: 900                         │
  │  }                                         │
  │ ◄──────────────────────────────────────────│
  │                                            │
  │  (Claude Code stores tokens locally)       │
```

### Step 9: User Calls an MCP Tool

Now the user is connected. They use Claude Code to call a tool.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Terminal (Claude Code)                                             │
│                                                                     │
│  You: "List my Tigris buckets"                                      │
│                                                                     │
│  Claude: I'll check your Tigris buckets...                          │
│          [Calling tool: tigris_list_buckets]                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Step 10: MCP Request with Token Validation

Claude Code sends the tool call to your MCP server.

```
Claude Code                               Your MCP Server
  │                                            │
  │  POST /mcp                                 │
  │  Authorization: Bearer eyJhbG...           │
  │  Content-Type: application/json            │
  │  {                                         │
  │    "jsonrpc": "2.0",                       │
  │    "method": "tools/call",                 │
  │    "params": {                             │
  │      "name": "list_tigris_buckets"         │
  │    }                                       │
  │  }                                         │
  │ ──────────────────────────────────────────►│
  │                                            │
  │                      ┌─────────────────────┤
  │                      │ 1. Extract JWT      │
  │                      │                     │
  │                      │ 2. Fetch JWKS from  │
  │                      │    /jwks endpoint   │
  │                      │    (cached)         │
  │                      │                     │
  │                      │ 3. Verify signature │
  │                      │                     │
  │                      │ 4. Extract 'sub'    │
  │                      │    claim = sessionId│
  │                      └─────────────────────┤
  │                                            │
  │                      ┌─────────────────────┤
  │                      │ 5. Load from Keyv:  │
  │                      │    session:{sub}    │
  │                      │                     │
  │                      │ 6. Check expiresAt  │
  │                      │    vs current time  │
  │                      │                     │
  │                      │ If expires in <60s: │
  │                      │   → Refresh IdP tok │
  │                      │   → Update session  │
  │                      └─────────────────────┤
  │                                            │
  │                      ┌─────────────────────┤
  │                      │ 7. Attach to req:   │
  │                      │                     │
  │                      │ req.user = {        │
  │                      │   accountId,        │
  │                      │   userId,           │
  │                      │   claims,           │
  │                      │   tokenSet: {       │
  │                      │     accessToken, ←──┼── Use this for
  │                      │     idToken,        │   upstream APIs
  │                      │     refreshToken    │
  │                      │   },                │
  │                      │   customData        │
  │                      │ }                   │
  │                      └─────────────────────┤
```

### Step 11: Tool Executes with IdP Token

Your tool handler uses the IdP access token to call upstream APIs.

```javascript
// In your MCP tool handler
handleMcpRequest(async (req, res) => {
  const user = req.user; // ← Populated by auth middleware

  // Use IdP access token to call Upstream API
  const response = await fetch('https://api.upstream.com/buckets', {
    headers: {
      Authorization: `Bearer ${user.tokenSet.accessToken}`, // ← IdP token
    },
  });

  const buckets = await response.json();
  return { buckets };
});
```

```
Your MCP Server                            Upstream API
  │                                            │
  │  GET /buckets                              │
  │  Authorization: Bearer idp_access_token    │
  │ ──────────────────────────────────────────►│
  │                                            │
  │  [{ id: 1, name: "test-bucket" }, ...]     │
  │ ◄──────────────────────────────────────────│
```

### Step 12: Response Back to User

```
Your MCP Server                           Claude Code
  │                                            │
  │  {                                         │
  │    "jsonrpc": "2.0",                       │
  │    "result": {                             │
  │      "buckets": [...]                      │
  │    }                                       │
  │  }                                         │
  │ ──────────────────────────────────────────►│
  │                                            │
  │  Claude displays results to user           │
```

---

### How Cookies Work in the Auth Flow

Cookies maintain state during the browser-based OAuth flow (Steps 3-7):

```
┌─────────────────────────────────────────────────────────────────────┐
│  Why Cookies?                                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  The OAuth flow involves multiple browser redirects:                │
│                                                                     │
│  1. /authorize     → Sets cookie with session ID                    │
│  2. → IdP login    → Cookie persists (browser handles it)           │
│  3. /callback      → Cookie identifies which auth flow this is      │
│  4. → redirect_uri → Flow complete                                  │
│                                                                     │
│  Without cookies, we couldn't link the callback to the original     │
│  authorization request (multiple users could be authenticating).    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

```
Browser                                  Your MCP Server
  │                                            │
  │  GET /authorize?client_id=xyz              │
  │ ──────────────────────────────────────────►│
  │                                            │
  │  302 Redirect to IdP                       │
  │  Set-Cookie: _session=abc123; HttpOnly     │ ← Session cookie
  │ ◄──────────────────────────────────────────│
  │                                            │
  │  ... user logs in at IdP ...               │
  │                                            │
  │  GET /callback?code=xyz                    │
  │  Cookie: _session=abc123                   │ ← Same cookie sent back
  │ ──────────────────────────────────────────►│
  │                                            │
  │                      ┌─────────────────────┤
  │                      │ Use cookie to find: │
  │                      │ - interactionUid    │
  │                      │ - PKCE verifier     │
  │                      │ - state/nonce       │
  │                      └─────────────────────┤
```

**Cookie Configuration:**

| Setting    | Development | Production            |
| ---------- | ----------- | --------------------- |
| `secure`   | `false`     | `true` (HTTPS only)   |
| `sameSite` | `lax`       | `none` (cross-origin) |
| `httpOnly` | `true`      | `true`                |
| `maxAge`   | 30 days     | 30 days               |

The `secret` option in `BaseOidcOptions` is used to sign these cookies.

---

### Data Stored in Keyv (Summary)

After the complete flow, here's what's in your Keyv store:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Keyv Store                                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  oidc:Client:xyz                    ← Claude Code's registration    │
│  ├─ client_id: "xyz"                                                │
│  ├─ client_secret: "..."                                            │
│  ├─ redirect_uris: ["http://127.0.0.1:*/..."]                       │
│  └─ TTL: 14 days                                                    │
│                                                                     │
│  session:abc123                     ← User's session                │
│  ├─ userId: "auth0|user123"                                         │
│  ├─ claims: { email, name, picture }                                │
│  ├─ tokenSet: { accessToken, idToken, refreshToken, expiresAt }     │
│  ├─ customData: { organizations: [...] }                            │
│  └─ TTL: 30 days                                                    │
│                                                                     │
│  oidc:AccessToken:def456            ← Active access token           │
│  └─ TTL: 15 minutes                                                 │
│                                                                     │
│  oidc:RefreshToken:ghi789           ← Refresh token                 │
│  └─ TTL: 30 days                                                    │
│                                                                     │
│  oidc:Grant:jkl012                  ← Consent record                │
│  └─ TTL: 14 days                                                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Token Validation

```
// From src/mcp/auth-provider.ts:221-223
const { payload } = await jwtVerify(token, JWKS, {
  issuer: oidcBaseUrl,
});
```

The `jwtVerify()` function from the jose library does all of the following:

| Check                  | What It Does                                                       | Fails If                                         |
| ---------------------- | ------------------------------------------------------------------ | ------------------------------------------------ |
| Signature Verification | Cryptographically verifies the JWT was signed by a key in the JWKS | Token was tampered with or signed by unknown key |
| Expiration (exp)       | Checks the token hasn't expired                                    | exp claim is in the past                         |
| Not Before (nbf)       | Checks the token is already valid                                  | nbf claim is in the future (if present)          |
| Issuer (iss)           | Checks token was issued by expected OIDC server                    | iss doesn't match oidcBaseUrl                    |
| Algorithm (alg)        | Ensures the algorithm matches what's expected                      | Algorithm mismatch or none algorithm attack      |
| Key ID (kid)           | Finds the correct key in JWKS to verify with                       | No matching key found                            |

#### What's NOT Checked (by default)

The current implementation doesn't check:

| Check                | Why Not                                        |
| -------------------- | ---------------------------------------------- |
| Audience (aud)       | Not passed to jwtVerify() - could be added     |
| Token Revocation     | Would require checking a revocation list/store |
| Real-time IdP status | JWT verification is offline by design          |

Visual: What Happens During Verification

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  jwtVerify(token, JWKS, { issuer: oidcBaseUrl })                        │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  Token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xMjM0In0.eyJpc3MiOi...       │
  │                                                                         │
  │  Step 1: Parse JWT Header                                               │
  │  ─────────────────────────                                              │
  │  {                                                                      │
  │    "alg": "RS256",        ◄── Must be RS256 (not "none"!)               │
  │    "kid": "key-1234",     ◄── Used to find correct public key           │
  │    "typ": "at+jwt"                                                      │
  │  }                                                                      │
  │                                                                         │
  │  Step 2: Fetch/Use Cached JWKS                                          │
  │  ─────────────────────────────                                          │
  │  Find key with kid="key-1234" in JWKS                                   │
  │  {                                                                      │
  │    "keys": [                                                            │
  │      { "kid": "key-1234", "kty": "RSA", "n": "...", "e": "..." }        │
  │    ]                                                                    │
  │  }                                                                      │
  │                                                                         │
  │  Step 3: Verify Signature (Cryptographic)                               │
  │  ─────────────────────────────────────────                              │
  │  RSA-SHA256(                                                            │
  │    base64url(header) + "." + base64url(payload),                        │
  │    publicKey                                                            │
  │  ) === signature                                                        │
  │                                                                         │
  │  ✓ If signature matches → token is authentic (not tampered)             │
  │  ✗ If signature fails → throw error                                     │
  │                                                                         │
  │  Step 4: Verify Claims                                                  │
  │  ─────────────────────                                                  │
  │  {                                                                      │
  │    "iss": "http://localhost:4001",  ◄── Must match oidcBaseUrl ✓        │
  │    "sub": "user-session-id",                                            │
  │    "exp": 1704067200,               ◄── Must be in future ✓             │
  │    "iat": 1704066300,                                                   │
  │    "client_id": "cursor",                                               │
  │    "scope": "openid email"                                              │
  │  }                                                                      │
  │                                                                         │
  │  Step 5: Return Payload                                                 │
  │  ──────────────────────                                                 │
  │  If all checks pass → return { payload, protectedHeader }               │
  │  If any check fails → throw JWTVerificationFailed error                 │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```
