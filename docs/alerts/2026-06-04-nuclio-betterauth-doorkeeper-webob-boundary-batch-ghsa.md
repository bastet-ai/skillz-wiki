# Nuclio, Better Auth, Doorkeeper, and WebOb boundary batch

## Operator value

GitHub Advisory Database items published on 2026-06-04 surfaced four reusable offensive-testing patterns worth preserving for authorized assessments:

- Nuclio Dashboard project write APIs can miss project-membership authorization on destructive write paths.
- Better Auth device authorization can let any authenticated session approve or deny a pending device code before the intended user claims it.
- Doorkeeper OpenID Connect dynamic client registration can create public clients that still receive a `client_secret`, allowing token endpoint authentication with only the public `client_id`.
- WebOb redirect normalization can turn control characters plus `//` into a cross-origin `Location` header.

Treat these as boundary checks: identity must bind to the target project, device code, OAuth client type, and redirect origin before side effects occur.

## Affected surfaces

### Nuclio Dashboard project write authorization

- Advisory: [GHSA-m8xg-8xg9-mxhm / CVE-2026-45730](https://github.com/advisories/GHSA-m8xg-8xg9-mxhm)
- Product: Nuclio / `github.com/nuclio/nuclio`
- Affected versions: before `0.0.0-20260513101907-1915cd26d514`
- Required position: authenticated low-privilege Nuclio Dashboard user who is not a member of the target project
- Boundary: `GET /api/projects` enforces project membership, while `PUT /api/projects/{id}` and `DELETE /api/projects` can construct permission options without the member list and bypass OPA filtering

### Better Auth device authorization code ownership

- Advisory: [GHSA-cq3f-vc6p-68fh / CVE-2026-45337](https://github.com/advisories/GHSA-cq3f-vc6p-68fh)
- Product: `better-auth`
- Affected versions: `>= 1.6.0, < 1.6.11`
- Required configuration: `deviceAuthorization()` plugin enabled
- Required position: authenticated attacker who observes a pending `user_code` before the intended user completes verification
- Boundary: `POST /device/approve` and `POST /device/deny` must be tied to the session that claimed the pending device row

### Doorkeeper OpenID Connect dynamic client registration

- Advisory: [GHSA-m6vc-f87m-cc2h / CVE-2026-44476](https://github.com/advisories/GHSA-m6vc-f87m-cc2h)
- Product: `doorkeeper-openid_connect`
- Affected version: `1.9.0`
- Required configuration: Dynamic Client Registration explicitly enabled
- Required position: ability to register or learn a dynamically registered `client_id`
- Boundary: public OAuth clients must not authenticate at the token endpoint as confidential clients using a blank or missing secret

### WebOb redirect Location normalization

- Advisory: [GHSA-fh3h-vg37-cc95 / CVE-2026-44889](https://github.com/advisories/GHSA-fh3h-vg37-cc95)
- Product: `webob`
- Affected versions: `<= 1.8.9`
- Required position: ability to influence an application redirect target that is assigned to `Response.location`
- Boundary: application-local redirect targets must not normalize into attacker-controlled network-path references such as `//attacker.example/path`

## Recon workflow

1. Confirm that scope permits authenticated application-boundary testing and that destructive operations are either prohibited or explicitly lab-scoped.
2. Inventory exposed components from safe evidence:
   - `go.mod`, Helm charts, images, or admin banners for Nuclio;
   - `package-lock.json`, `pnpm-lock.yaml`, or app auth configuration for Better Auth;
   - `Gemfile.lock` and OAuth initializer settings for Doorkeeper OpenID Connect;
   - Python dependency manifests or WSGI framework stacks for WebOb.
3. Prioritize targets where the vulnerable feature is reachable:
   - multi-tenant Nuclio dashboards with low-privilege accounts;
   - device-flow login UX, CLI pairing, TV/device auth, support workflows, or screen-share-heavy onboarding;
   - OAuth providers that allow dynamic client registration;
   - redirect endpoints that accept user-controlled `next`, `return_to`, `continue`, or post-login destinations.
4. Capture exact version and feature evidence before probing. A dependency match without the relevant feature path is not enough.

## Safe validation patterns

### Nuclio project write authorization drift

Use a non-production project or a lab clone. Do not test project deletion against live tenant resources unless the program owner has created an explicit disposable target.

1. Create or request two accounts:
   - `owner@example.test` with access to `skillz-owned-project`;
   - `lowpriv@example.test` with any valid Dashboard session but no membership in that project.
2. Verify the read boundary from the low-privilege session:

   ```http
   GET /api/projects HTTP/1.1
   Authorization: Bearer LOW_PRIV_TOKEN
   ```

   Expected safe result: the target project is absent.

3. Attempt a harmless metadata-only write against a disposable project, such as changing a canary description or label:

   ```http
   PUT /api/projects/skillz-owned-project HTTP/1.1
   Authorization: Bearer LOW_PRIV_TOKEN
   Content-Type: application/json

   {"metadata":{"labels":{"skillz-authz-canary":"lowpriv-write"}}}
   ```

4. Interpret results:
   - **Contained:** write is rejected by project membership policy.
   - **Vulnerable boundary:** low-privilege user can modify project metadata or trigger project deletion/write side effects despite read denial.

### Better Auth pending device-code hijack

Use a lab tenant and two controlled accounts. Never harvest real user codes from production screens, calls, or logs.

1. Start a device authorization flow from a test client and record only the lab `user_code`.
2. Before the intended account approves it, sign in as a separate attacker-controlled account.
3. Submit the observed code through the verification/approval endpoint or custom verification UI.
4. Confirm which account the polling device is bound to:
   - **Contained:** approve/deny requires the same session that claimed the pending row, or the first authenticated verification step owns the row.
   - **Vulnerable boundary:** the attacker-controlled session can approve or deny another pending user code.

Evidence should show timestamps and account IDs for the pending code owner, approver, and resulting token subject. Redact real tokens.

### Doorkeeper dynamic client registration client-type confusion

Validate only against an OAuth lab client or a tenant where the owner has authorized client registration tests.

1. Confirm Dynamic Client Registration is enabled.
2. Register a canary client:

   ```http
   POST /oauth/registration HTTP/1.1
   Content-Type: application/json

   {
     "client_name": "skillz-dcr-canary",
     "redirect_uris": ["https://client.example.test/callback"],
     "scope": "openid"
   }
   ```

3. Record whether the response returns both `client_id` and `client_secret` while the server stores the application as non-confidential/public.
4. Attempt token endpoint authentication without a secret for a grant type allowed by the lab configuration:

   ```http
   POST /oauth/token HTTP/1.1
   Content-Type: application/x-www-form-urlencoded

   grant_type=client_credentials&client_id=CLIENT_ID
   ```

5. Interpret results:
   - **Contained:** token endpoint rejects missing/blank secret for confidential behavior, or the client is consistently public with no secret-based methods advertised.
   - **Vulnerable boundary:** a token is issued with only public `client_id` knowledge where the provider advertises secret-based client authentication.

### WebOb redirect canonicalization bypass

Use an endpoint where redirect targets are intended to remain same-origin. Avoid phishing or real user interaction; capture only server responses.

1. Find a redirect parameter in scope, for example:

   ```text
   https://app.example.test/login?next=/dashboard
   ```

2. Send canary redirect targets containing ASCII tab, carriage return, or newline before a double slash. Encode controls if the frontend or proxy requires it:

   ```text
   /%09/redirect-canary.example.test/path
   /%0d/redirect-canary.example.test/path
   /%0a/redirect-canary.example.test/path
   ```

3. Inspect the raw response, not browser behavior alone:

   ```bash
   curl -i 'https://app.example.test/login?next=/%09/redirect-canary.example.test/path'
   ```

4. Interpret results:
   - **Contained:** `Location` remains a same-origin path or the input is rejected.
   - **Vulnerable boundary:** `Location` becomes `https://redirect-canary.example.test/path` or another attacker-controlled origin.

## Evidence to capture

- Dependency and feature evidence: package version, lockfile line, feature flag, plugin configuration, or owner-provided SBOM.
- Account and tenant model for authorization tests, using only controlled users and disposable resources.
- Raw HTTP requests and responses that show the boundary crossing without exposing real credentials or tokens.
- For OAuth/device-flow checks, token subjects and client IDs should be redacted or canary-only.
- For redirect checks, include the exact encoded payload and normalized `Location` header.

## Report framing

Frame these as missing binding checks before sensitive side effects:

- Nuclio: authenticated does not equal authorized for target project write/delete.
- Better Auth: observed user code does not equal ownership of a pending device authorization row.
- Doorkeeper: public `client_id` knowledge must not satisfy confidential client authentication.
- WebOb: a path-like redirect target must not normalize into an attacker-controlled origin after parser cleanup.

Avoid destructive validation in production. A metadata canary, controlled device code, lab OAuth client, or raw redirect response is enough for a high-quality proof.

## Sources

- GitHub Advisory Database: [GHSA-m8xg-8xg9-mxhm / CVE-2026-45730](https://github.com/advisories/GHSA-m8xg-8xg9-mxhm)
- GitHub Advisory Database: [GHSA-cq3f-vc6p-68fh / CVE-2026-45337](https://github.com/advisories/GHSA-cq3f-vc6p-68fh)
- GitHub Advisory Database: [GHSA-m6vc-f87m-cc2h / CVE-2026-44476](https://github.com/advisories/GHSA-m6vc-f87m-cc2h)
- GitHub Advisory Database: [GHSA-fh3h-vg37-cc95 / CVE-2026-44889](https://github.com/advisories/GHSA-fh3h-vg37-cc95)
- RFC 8628 OAuth 2.0 Device Authorization Grant, session-spying risk: https://www.rfc-editor.org/rfc/rfc8628#section-5.5
