# Cross-Domain Authentication Testing Guide

This guide provides detailed procedures for handling and testing cross-domain authentication flows (SSO, OAuth/OIDC, SAML) during penetration tests.

## Detection Checklist

Before starting authenticated testing, determine if cross-domain auth is in use:

- [ ] Pre-flight redirect detected to different domain (`curl -sk -L -o /dev/null -w '%{url_effective}' <target>/login`)
- [ ] Auth provider domain identified (e.g., Keycloak, Auth0, Okta, ADFS)
- [ ] OIDC well-known configuration retrieved (if OIDC)
- [ ] SAML metadata retrieved (if SAML)
- [ ] All domains registered with `register_scope()`
- [ ] Cookie jar created (`touch ./runtime/engagements/<eid>/cookies.txt`)
- [ ] Login flow documented step-by-step
- [ ] Cookie jar verified with valid session

## Cookie Jar Fundamentals

### Creating and Using the Cookie Jar

```bash
# Create cookie jar

# Standard cross-domain request pattern
  -b ./runtime/engagements/<eid>/cookies.txt \
  -c ./runtime/engagements/<eid>/cookies.txt \
  -D- <url>

# Inspect cookie jar contents

# Clear cookie jar (start fresh session)
```

### Cookie Jar Format

The Netscape cookie jar format has these columns:
```
# domain  httponly  path  secure  expiry  name  value
.example.com	TRUE	/	TRUE	0	session	abc123
auth.example.com	FALSE	/	TRUE	1707400000	KEYCLOAK_SESSION	xyz789
```

### Debugging Redirect Chains

To trace each redirect hop individually (without following):
```bash
  -b ./runtime/engagements/<eid>/cookies.txt \
  -c ./runtime/engagements/<eid>/cookies.txt \
  <url>
```
Look for `Location:` headers and `Set-Cookie:` headers at each hop.

## OAuth 2.0 Authorization Code Flow

This is the most common SSO flow (used by Keycloak, Auth0, Okta, Google, GitHub, etc.).

### Step 1: Discover OIDC Configuration

```bash
```

Key fields to note:
- `authorization_endpoint` — where users are redirected to log in
- `token_endpoint` — where auth codes are exchanged for tokens
- `userinfo_endpoint` — where user details can be retrieved
- `jwks_uri` — public keys for JWT verification
- `grant_types_supported` — each grant type is an attack surface
- `scopes_supported` — available permission scopes

### Step 2: Initiate the Auth Flow

```bash
  -b ./runtime/engagements/<eid>/cookies.txt \
  -c ./runtime/engagements/<eid>/cookies.txt \
  https://app.example.com/login
```

The redirect chain typically looks like:
1. `app.example.com/login` → 302 to auth provider
2. `auth.example.com/auth?client_id=...&redirect_uri=...&response_type=code&scope=openid&state=...` → login form
3. User submits credentials → 302 back to app
4. `app.example.com/callback?code=AUTH_CODE&state=STATE` → exchanges code for token

### Step 3: Submit Credentials

Extract the login form action URL from the HTML response, then POST credentials:

```bash
  -b ./runtime/engagements/<eid>/cookies.txt \
  -c ./runtime/engagements/<eid>/cookies.txt \
  -X POST -d "username=USER&password=PASS" \
  "https://auth.example.com/auth/realms/REALM/login-actions/authenticate?session_code=...&client_id=..."
```

### Step 4: Verify Session

```bash
  -b ./runtime/engagements/<eid>/cookies.txt \
  https://app.example.com/dashboard
```

If you get 200 with authenticated content, the login flow worked.

### Alternative Grant Types to Test

If the standard flow fails, try these directly against the token endpoint:

```bash
# Password grant (if supported)
  -d "grant_type=password&username=USER&password=PASS&client_id=CLIENT_ID" \
  https://auth.example.com/token

# Client credentials grant
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=SECRET" \
  https://auth.example.com/token

# Implicit grant (change response_type in auth URL)
# Change response_type=code to response_type=token in the authorization URL

# Device code flow
  -d "client_id=CLIENT_ID&scope=openid" \
  https://auth.example.com/devicecode
```

## SAML Authentication

### SP-Initiated Flow

**Step 1: Initiate from the Service Provider**
```bash
  -b ./runtime/engagements/<eid>/cookies.txt \
  -c ./runtime/engagements/<eid>/cookies.txt \
  https://app.example.com/login
```

The SP redirects to the IdP with a SAMLRequest parameter (base64-encoded XML).

**Step 2: Submit Credentials at the IdP**
Extract the login form action URL from the IdP's HTML response and POST credentials.

**Step 3: Complete the SAML Assertion**
The IdP responds with an HTML form containing a SAMLResponse (auto-submitted via JavaScript).
Extract the SAMLResponse and RelayState values, then POST them:

```bash
  -b ./runtime/engagements/<eid>/cookies.txt \
  -c ./runtime/engagements/<eid>/cookies.txt \
  -X POST -d "SAMLResponse=BASE64_VALUE&RelayState=RELAY_VALUE" \
  https://app.example.com/saml/acs
```

### IdP-Initiated Flow

Some IdPs allow direct login without an SP-initiated request. Check:
```bash
```

### SAML-Specific Attack Vectors

- **Signature wrapping**: Modify the assertion while keeping the signature valid
- **XXE in SAMLRequest/SAMLResponse**: Inject XML entities
- **Replay attacks**: Reuse a captured SAMLResponse
- **Missing signature validation**: Remove the signature entirely

## Provider-Specific Procedures

### Keycloak

**Discovery:**
```bash
# Realm configuration

# Admin console (often exposed)

# Account console
```

**Login form action URL pattern:**
```
https://keycloak.example.com/realms/REALM/login-actions/authenticate?session_code=...&execution=...&client_id=...&tab_id=...
```

**Known endpoints to check:**
- `/realms/REALM/protocol/openid-connect/auth`
- `/realms/REALM/protocol/openid-connect/token`
- `/realms/REALM/protocol/openid-connect/userinfo`
- `/realms/REALM/protocol/openid-connect/certs` (JWKS)
- `/realms/REALM/clients-registrations/default` (client registration)

### Auth0

**Discovery:**
```bash
# Tenant configuration

# Check for exposed management API
```

**Login form pattern:**
Auth0 uses a Universal Login page. The credentials form may be JavaScript-rendered.
If curl can't extract the form, try the password grant directly:
```bash
  -H "Content-Type: application/json" \
  -d '{"grant_type":"password","username":"USER","password":"PASS","client_id":"CLIENT_ID","audience":"API_IDENTIFIER"}' \
  https://TENANT.auth0.com/oauth/token
```

### Okta

**Discovery:**
```bash
# Org configuration

# Authentication API
  -H "Content-Type: application/json" \
  -d '{"username":"USER","password":"PASS"}' \
  https://ORG.okta.com/api/v1/authn
```

**Known endpoints:**
- `/api/v1/authn` — Primary authentication
- `/api/v1/sessions` — Session management
- `/oauth2/default/v1/authorize` — OAuth authorization
- `/oauth2/default/v1/token` — Token endpoint

### ADFS (Active Directory Federation Services)

**Discovery:**
```bash
```

## Cross-Domain Attack Surface Checklist

After authenticating, test these cross-domain-specific vulnerabilities:

### Token & Cookie Analysis
- [ ] Inspect cookie jar for tokens scoped to the wrong domain
- [ ] Check if auth provider cookies are accessible from the app domain
- [ ] Verify cookie `Domain` attribute isn't overly broad (e.g., `.example.com` when it should be `app.example.com`)
- [ ] Check if session tokens appear in URL parameters during redirects (leakable via Referer header)
- [ ] Test if auth tokens are sent to third-party resources (analytics, CDN)

### OAuth/OIDC-Specific
- [ ] `redirect_uri` validation bypass (see WSTG-ATHZ-05 Step 2)
- [ ] `state` parameter validation across domains
- [ ] Authorization code replay
- [ ] Token scope escalation
- [ ] PKCE bypass (for public clients)
- [ ] JWT audience (`aud`) claim validation — can a token for one app be used on another?
- [ ] Token issued by one IdP used against another IdP's resource server

### Cross-Domain Session
- [ ] Does logging out of the app also invalidate the IdP session?
- [ ] Does logging out of the IdP invalidate all app sessions?
- [ ] Can you fixate the IdP session token?
- [ ] Is the app vulnerable to session confusion between subdomains?

### CORS Between Domains
- [ ] Can the app domain make credentialed requests to the auth domain?
- [ ] Does the auth domain have permissive CORS that allows token extraction?

## Troubleshooting

### "Login flow requires JavaScript"
The auth provider renders the login form client-side (common with Auth0 Universal Login, some Keycloak themes):
1. Try extracting the form action from the HTML source
2. Try the password grant directly against the token endpoint
3. Ask the user to log in via browser and provide the session cookie manually

### "Auth provider returns HTML form with SAMLResponse"
This is normal for SAML flows — the IdP returns an HTML form that auto-submits:
1. Extract the SAMLResponse value from the HTML `<input type="hidden" name="SAMLResponse" value="...">`
2. Extract RelayState if present
3. POST both to the SP's ACS endpoint

### "Cookie jar has expired tokens"
1. Clear the cookie jar: `sh -c '> ./runtime/engagements/<eid>/cookies.txt'`
2. Re-run the full authentication flow
3. Verify with an authenticated request

### "Redirect loop"
Follow redirects one at a time (without `-L`) to identify the loop point:
```bash
  -b ./runtime/engagements/<eid>/cookies.txt \
  -c ./runtime/engagements/<eid>/cookies.txt \
  <url>
```
Check if a missing cookie or expired session is causing the loop.

### "401/403 after successful login"
1. Check the cookie jar — does it have the expected session cookie?
2. Verify the cookie's `Domain` and `Path` match the request URL
3. Check if the app expects a Bearer token instead of cookies
4. Some apps use the auth code/token in a custom header — inspect the login response carefully

## Authentication Failure Escalation Procedure (MANDATORY)

When automated authentication fails, follow this escalation ladder. **Do NOT skip steps or silently mark tests as N/A.**

### Escalation Ladder

**Level 1: Alternative Grant Types** (try ALL of these)
1. Password grant: `POST /token` with `grant_type=password`
2. Client credentials: `POST /token` with `grant_type=client_credentials`
3. Implicit grant: Change `response_type=code` to `response_type=token` in auth URL
4. Device code flow: `POST /devicecode`
5. Check the OIDC well-known config for `grant_types_supported` — try ALL listed grants

```bash
# Example: try all grant types from OIDC config
```

**Level 2: PKCE Helper Script**
If the flow requires PKCE (code_challenge/code_verifier), use the helper script:
```bash
  --auth-url https://auth.example.com \
  --realm REALM --client-id CLIENT_ID \
  --username USER --password PASS \
  --redirect-uri https://app.example.com/callback
```

**Level 3: Headless Browser**
If the login page is JavaScript-rendered (Auth0 Universal Login, custom Keycloak themes):
```bash
  --url https://app.example.com/login \
  --username USER --password PASS \
  --cookie-jar ./runtime/engagements/<eid>/cookies.txt
```

**Level 4: Token Extraction from JavaScript**
Search discovered JavaScript files for hardcoded tokens, API keys, or client secrets:
```bash
```

**Level 5: Ask the User (MANDATORY if Levels 1-4 fail)**
Present the user with clear instructions for providing a session cookie or Bearer token manually:

> "I was unable to complete authentication automatically. The application uses [PKCE/Auth0/etc.] which requires browser interaction.
>
> Please provide ONE of the following:
> 1. **Session cookie**: Log in via browser → DevTools (F12) → Application → Cookies → copy the session cookie name and value
> 2. **Bearer token**: Log in via browser → DevTools → Network → make any request → copy the Authorization header value
> 3. **Tell me you're logged in**: If Burp proxy is running, log in via browser and I will extract cookies from the proxy history
>
> Without authentication, I can only test ~30% of the application."

**Level 6: Proceed with Unauthenticated Testing**
If the user cannot provide credentials:
- Test ALL unauthenticated endpoints (see AGENTS.md "Tests That Don't Require Authentication")
- Mark auth-required tests as `skipped` (**NOT** `not_applicable`) with note: "Authentication unavailable — all automated methods exhausted, user unable to provide token"
- Log an Informational finding documenting the auth failure and its impact on coverage

### What NOT to Do

- **Do NOT** mark auth-dependent tests as `not_applicable` — use `skipped` with explanation
- **Do NOT** silently give up after one auth method fails
- **Do NOT** proceed to Phase 4 without attempting all escalation levels
- **Do NOT** generate a report claiming "100% coverage" when >50% of tests were skipped due to auth
- **Do NOT** assume PKCE means "impossible to authenticate" — use the helper scripts
