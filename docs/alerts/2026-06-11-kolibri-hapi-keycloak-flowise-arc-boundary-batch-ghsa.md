# Kolibri SSRF, Hapi static-file, Keycloak IDP, Flowise vector-store, and Arc debug boundary checks

Source: hourly offensive-security scan, 2026-06-11. Primary entries: GitHub advisories [GHSA-4mj9-pf4r-cqrc](https://github.com/advisories/GHSA-4mj9-pf4r-cqrc) / CVE-2026-48053, [GHSA-rcvq-m9j9-6f4g](https://github.com/advisories/GHSA-rcvq-m9j9-6f4g) / CVE-2026-48049, [GHSA-m6qj-3mpp-57v8](https://github.com/advisories/GHSA-m6qj-3mpp-57v8) / CVE-2026-9087, [GHSA-hmg2-jjjx-jcp2](https://github.com/advisories/GHSA-hmg2-jjjx-jcp2) / CVE-2026-46444, and [GHSA-j93g-rp6m-j32m](https://github.com/advisories/GHSA-j93g-rp6m-j32m) / CVE-2026-48050.

June 26 Keycloak update: GitHub advisories [GHSA-g8vr-x4qh-25qg](https://github.com/advisories/GHSA-g8vr-x4qh-25qg) / CVE-2026-8830, [GHSA-83c4-ffjp-mxp9](https://github.com/advisories/GHSA-83c4-ffjp-mxp9) / CVE-2026-8922, and [GHSA-hm32-hfmw-rhvg](https://github.com/advisories/GHSA-hm32-hfmw-rhvg) / CVE-2026-7500.

June 30 Keycloak UMA update: GitHub advisories [GHSA-c739-f6xw-6pv2](https://github.com/advisories/GHSA-c739-f6xw-6pv2) / CVE-2026-4630 and [GHSA-933f-rg6j-f46p](https://github.com/advisories/GHSA-933f-rg6j-f46p) / CVE-2026-37981.

July 1 Keycloak update: GitHub advisories [GHSA-rr5q-3xwr-f323](https://github.com/advisories/GHSA-rr5q-3xwr-f323) / CVE-2026-9704, [GHSA-wcvj-vpvw-9rr5](https://github.com/advisories/GHSA-wcvj-vpvw-9rr5) / CVE-2026-9689, [GHSA-33j3-g875-37rp](https://github.com/advisories/GHSA-33j3-g875-37rp) / CVE-2026-9792, [GHSA-32h4-44jj-c5vx](https://github.com/advisories/GHSA-32h4-44jj-c5vx) / CVE-2026-9795, [GHSA-4q93-v92x-p89f](https://github.com/advisories/GHSA-4q93-v92x-p89f) / CVE-2026-9791, [GHSA-q6h7-xxp7-7429](https://github.com/advisories/GHSA-q6h7-xxp7-7429) / CVE-2026-9798, [GHSA-p3v8-fm5p-v84h](https://github.com/advisories/GHSA-p3v8-fm5p-v84h) / CVE-2026-9793, and [GHSA-pq65-77rc-7r8c](https://github.com/advisories/GHSA-pq65-77rc-7r8c) / CVE-2026-9796.

This batch is durable because each advisory exposes a reusable operator pattern: server-side URL fetches that reflect remote responses, string-prefix filesystem confinement, identity-provider proof scoping, low-privilege AI-workflow object control, and accidentally public Go `pprof` debug surfaces.

## What changed

- **Kolibri unauthenticated reflected SSRF** — several Kolibri endpoints accepted a caller-controlled `baseurl`, fetched remote Kolibri-shaped APIs, followed redirects, and reflected the fetched JSON body. The clearest unauthenticated route is `GET /api/auth/remotefacilityuser`; adjacent routes include remote-facility authenticated user, setup-wizard LOD data on unprovisioned devices, and network-location facility listing.
- **`@hapi/inert` sibling-prefix static file escape** — `@hapi/inert` `>= 4.0.0, <= 7.1.0` enforced `confine` with a raw absolute-path string-prefix check. A served directory such as `/app/static` could be escaped into a sibling like `/app/static-secret` via encoded traversal if that sibling path shared the same prefix and was readable by the process.
- **Keycloak identity-provider account-link proof reuse** — Keycloak `keycloak-services < 26.6.3` keyed cross-session verification proof only by local user ID and IdP alias, not by the upstream identity that was verified. A second upstream account on the same IdP could consume proof scoped for another identity and link into the victim local account.
- **Keycloak WebAuthn policy checked only in the browser** — Keycloak `keycloak-services <= 26.6.2` could let an authenticated user register a WebAuthn credential whose algorithms or parameters did not match realm policy when client-side JavaScript was manipulated.
- **Keycloak token introspection revocation drift** — Keycloak `keycloak-services <= 26.6.2` could report tokens as active when both realm-level and client-level `notBefore` policies were configured and the realm-level revocation should have invalidated the token.
- **Keycloak versioned Account API forced browsing** — Keycloak `keycloak-services <= 26.6.1` could leave five `/account/v1alpha1` REST endpoints reachable when the server was started with `--features-disabled=account,account-api`. The advisory notes the caller still needs permissions to use the API; the bug is that the versioned route family lacked the same feature gate as adjacent endpoints.
- **Keycloak UMA Protection API resource-server IDOR** — authenticated clients using Authorization Services Protection API endpoints could access or modify resource records owned by another Resource Server in the same realm when they knew the target resource UUID.
- **Keycloak Account Resources user lookup overreach** — an authenticated user who owns at least one UMA resource could query arbitrary username or email values and receive profile objects for unrelated realm users.
- **Keycloak token-exchange oversized `subject_token` fallback** — a low-privilege authenticated user could send an oversized `subject_token` JWT to the TokenEndpoint; when the token exceeded the server limit and was silently dropped, processing could fall back to client credentials and return the client's service-account permissions.
- **Keycloak redirect HTTP parameter pollution** — when a client accepts broad redirect URIs, crafted authentication URLs could manipulate duplicate or conflicting parameters so attacker-controlled data is prioritized over legitimate redirect data during the login flow.
- **Keycloak Client Policies ROPC executor bypass** — when selected OIDC Client Policies condition providers are used, the `reject-ropc-grant` executor can be silently bypassed, allowing ROPC token issuance even though policy says the grant should be blocked.
- **Keycloak FGAPv2 client scope-mapping escalation** — an administrator with limited client-management permissions can assign realm roles, including privileged roles, to a client's scope mapping despite intended Fine-Grained Admin Permissions controls.
- **Keycloak Organizations disabled-feature metadata leak** — a user with existing organization membership can still receive organization metadata through user-facing APIs or OIDC tokens with the `organization` scope after the Organizations feature is disabled.
- **Keycloak CIBA brute-force lock bypass** — a user account temporarily locked by repeated login failures could still receive Client-Initiated Backchannel Authentication flow attempts and token issuance when the attacker has valid client credentials.
- **Keycloak encrypted request-object signature bypass** — an OIDC request object supplied as JWE could be decrypted as raw JSON and processed without the configured request-object signature guarantee.
- **Keycloak name-based admin role TOCTOU** — a `manage-clients` administrator could exploit time-of-check/time-of-use drift in name-based admin role checks to create a persistent `realm-admin` composite role relationship.
- **Flowise OpenAI Assistants vector-store permission gap** — Flowise `<= 3.1.1` exposed vector-store CRUD/upload routes without per-operation permission checks. Any authenticated user with API access could create, modify, delete, or upload files to OpenAI Assistants vector stores outside their intended role.
- **Arc public Go `pprof` debug endpoints** — Arc builds before `v26.06.1` registered `net/http/pprof` handlers under `/debug/pprof/*` and added that path to public prefixes, allowing unauthenticated heap/goroutine/profile/trace access. Treat the useful signal as debug surface exposure and runtime-state leakage; CPU-burn is secondary and should not be stress-tested in production.

## Operator triage

1. **Map reachability first:** identify internet- or partner-reachable Kolibri, Hapi static-file apps, Keycloak brokers, Flowise workspaces, and Arc API ports. Confirm versions before probing.
2. **For Kolibri, inspect redirect behavior:** a hostile `baseurl` that first looks Kolibri-like and then redirects is the important primitive. Prioritize devices where remote-facility workflows or setup wizard endpoints are reachable without local authentication.
3. **For Hapi, inventory sibling names:** exploitation depends on a sibling directory whose absolute path begins with the served directory path. Look for `static` next to `static-private`, `public` next to `public-backup`, or `assets` next to `assets-secrets`.
4. **For Keycloak, separate IdP alias from upstream subject:** the finding requires external identity-provider account linking and more than one upstream account under the same IdP alias. Plain local-login account takeover is not implied without that broker workflow.
5. **For Keycloak, test server-side policy gates, not UI state:** WebAuthn registration, token introspection, and disabled Account API routes all need direct HTTP/API validation because the expected control may live in browser code, route discovery, or one policy layer but not the server-side endpoint that makes the decision.
6. **For Flowise, enumerate vector-store roles:** collect the lowest role/API token that can reach `/api/v1/openai-assistants-vector-store` and compare permitted UI actions with direct API actions.
7. **For Arc, test metadata reads only:** request cheap endpoints such as `/debug/pprof/` or a bounded goroutine listing in an isolated or approved environment. Avoid long `profile?seconds=` or `trace` requests on shared systems.

## Replayable validation boundaries

### Kolibri reflected SSRF

- Use only tester-controlled callback infrastructure or an approved lab internal URL. Do not probe cloud metadata, admin panels, or internal production services.
- Host a benign Kolibri-shaped response for `/api/public/info/`, then redirect the endpoint Kolibri fetches to a canary URL or a JSON canary body.
- Send one request to `GET /api/auth/remotefacilityuser?baseurl=<owned-url>` and record whether the Kolibri server fetches the canary and reflects the canary JSON.
- Evidence should include endpoint, version, unauthenticated/authenticated state, callback log, reflected canary string, and redirect chain. Stop at reachability/reflection proof.

### `@hapi/inert` sibling-prefix escape

- Validate only with synthetic sibling directories and marker files in lab or with customer-approved canaries.
- Confirm the served directory and sibling prefix relationship, for example `/srv/app/static` and `/srv/app/static-secret`.
- Request an encoded traversal path such as `/..%2fstatic-secret/skillz-inert-canary.txt` through the static route.
- A strong report compares: normal in-scope static file succeeds, non-prefix sibling fails, prefix-sharing sibling canary succeeds, and patched `7.1.1` rejects the same path.

### Keycloak broker proof scoping

- Use a test realm and disposable local/upstream accounts. Do not attempt account linking against real users.
- Configure one IdP alias and two upstream identities. Trigger verification proof for upstream identity A, then attempt to consume it from upstream identity B under the same IdP alias.
- The proof is positive only if B can link to the local account after A completed the verification step. Capture realm, IdP alias, account IDs as canary labels, and browser/session sequencing.
- Avoid framing as generic authentication bypass unless the brokered account-link chain is demonstrated end to end.

### Keycloak WebAuthn, token revocation, and Account API route-family checks

- Use a lab realm with disposable users, test clients, and synthetic credentials only. Do not enroll operator passkeys, reuse production IdP accounts, or test against real customer sessions.
- **WebAuthn policy check:** configure a restrictive realm WebAuthn policy, then submit a credential-registration flow where the client-side parameters are altered before the server receives `processAction()`. A useful proof compares UI-compliant registration, manipulated registration on the affected version, and patched `26.6.3+` rejection.
- **Token revocation drift:** configure both realm-level and client-level `notBefore` values, mint a disposable OIDC token, move the realm-level revocation boundary forward, and call introspection. The only evidence needed is the synthetic token label, policy timestamps, expected inactive state, and observed introspection result; never publish live tokens.
- **Disabled Account API forced browsing:** start Keycloak with `--features-disabled=account,account-api`, then probe paired route families as the same low-privilege test user: an endpoint that correctly returns the feature-disabled response and the corresponding `/account/v1alpha1` route that should be blocked. Keep write tests to disposable profile or preference fields.
- Report these as **server-side policy enforcement gaps**: browser WebAuthn policy to accepted credential, realm revocation policy to introspection result, or disabled feature flag to versioned REST route. Avoid claiming unauthenticated access when the advisory requires an authenticated or permissioned caller.

### Keycloak UMA resource and account-lookup authorization checks

- Preconditions: lab realm, Authorization Services enabled, two disposable Resource Servers or clients, two disposable users, and synthetic UMA resources only.
- For Protection API IDOR, create `resource-a` under Resource Server A and `resource-b` under Resource Server B. Authenticate as the client for A, then attempt GET/PUT/DELETE-style Protection API operations against B's resource UUID.
- Positive evidence is limited to a canary resource name, owner Resource Server ID, HTTP method, expected denial, and observed access or mutation. Do not delete real resources; if DELETE must be tested, use only a disposable marker resource.
- For Account Resources lookup, use a low-privilege user that owns one canary UMA resource. Query only disposable usernames/emails in the same lab realm and compare whether unrelated user profile objects are returned.
- Treat these as **same-realm authorization and object-ownership drift**, not unauthenticated account takeover. Keep PII out of evidence; use fake names, fake emails, and redacted profile fields.

### July 1 Keycloak token-exchange and redirect-parameter pollution update

- Preconditions: lab realm, disposable users, a test client with service-account roles, broad redirect URI configuration only in an isolated app, and synthetic tokens. Do not reuse production clients, IdPs, sessions, or real user tokens.
- **Oversized `subject_token` fallback:** mint a low-privilege synthetic token and create an oversized JWT-shaped `subject_token` canary that exceeds the documented server limit without containing real claims. Submit the token-exchange request as the low-privilege caller and compare expected denial with whether the response reflects the client's service-account roles. Evidence should show request shape, token labels, expected subject, returned subject/roles, and patched `26.6.3+` rejection.
- **Redirect parameter pollution:** configure a disposable client with intentionally broad redirect URI rules. Send paired authorization requests: one baseline with a single legitimate redirect value and one with duplicate/conflicting redirect-related parameters that should not override the legitimate destination. A positive proof shows the server choosing attacker-controlled redirect data after login. Use owned `example.invalid`-style domains or a local canary route; never target real users.
- Frame both as **server-side consistency and fallback failures**: oversized token input to unintended client-credential fallback, or duplicate redirect input to wrong destination selection. Avoid claiming unauthenticated access; the token-exchange issue requires an authenticated low-privilege caller and the redirect issue depends on client redirect configuration plus user interaction.

### July 1 Keycloak client-policy, scope-mapping, and organization-metadata update

- Preconditions: lab realm, disposable users, one low-privilege admin or client manager, test clients, synthetic realm roles, and no production identity-provider, service-account, or organization data.
- **ROPC policy bypass:** configure a Client Policy that should reject Resource Owner Password Credentials grants using the affected condition providers (`client-type`, `client-roles`, `client-attributes`, or `client-scopes`). Submit paired token requests from a disposable client: one policy path expected to reject ROPC and one affected condition path. Positive evidence is token issuance where policy expected denial. Redact tokens; record only route, client label, condition provider, grant type, and decision.
- **FGAPv2 scope mapping:** grant a test admin only limited client-management permissions. Attempt to add a high-privilege synthetic realm role to a disposable client's scope mapping and then mint a token through that client as a disposable user. Positive evidence is the unexpected role claim appearing in the canary token. Do not assign built-in production admin roles or mutate real clients.
- **Organizations disabled-feature metadata:** create a disposable organization and member, disable the Organizations feature as described by the deployment under test, then compare Account API and OIDC token responses with and without the `organization` scope. Positive evidence is synthetic organization metadata still present after the feature is disabled.
- Frame all three as **identity control-plane consistency gaps**: configured client policy to token grant, limited client admin to realm-role projection, or disabled organization feature to still-emitted authorization metadata. Avoid overclaiming unauthenticated impact; these advisories require specific clients, users, memberships, or limited-admin permissions.

### July 1 Keycloak CIBA, request-object, and admin-role TOCTOU follow-up

- Preconditions: lab realm, disposable users, test clients with only synthetic roles, CIBA enabled only for the test case, throwaway OIDC keys, and no production IdP, banking/FAPI, or admin clients.
- **CIBA lock bypass:** lock a disposable account through the normal failed-login path, then compare direct login denial with a CIBA request from a client that has only test credentials. Positive evidence is token issuance or continued authentication attempts after the account should be locked. Do not test real user accounts or run password-spray loops.
- **JWE request-object signature policy:** configure a client/realm policy that requires signed request objects. Submit paired authorization requests: a correctly signed control and an encrypted raw-JSON request object that should fail signature policy. Positive evidence is accepted unsigned claims after JWE decryption. Use synthetic claims and owned redirect URIs only.
- **Admin role TOCTOU:** give a disposable admin only `manage-clients`-style permissions. Attempt the documented name/race flow against synthetic realm roles and clients, then check whether a `realm-admin`-equivalent composite relationship persists after permission removal. Keep the role names clearly synthetic and avoid built-in production roles unless the lab requires a canary clone.
- Frame these as **alternate identity flow to lockout policy**, **encrypted request object to signature requirement**, and **client-admin name check to persistent realm-admin role projection**. Redact every token and session identifier; report decision tables, route names, client labels, and fixed-version denial instead of live credentials.

### Flowise vector-store authorization

- Use a low-privilege test user and an isolated workspace/vector store with disposable files.
- Compare the UI-permitted actions for that role with direct API calls to create/update/delete/upload under `/api/v1/openai-assistants-vector-store`.
- Prove only with inert canary files and object IDs. Do not upload payloads, delete production stores, or read real assistant documents.
- Useful evidence shows role, token type, route/method, target vector-store ID, expected permission, and actual result.

### Arc `pprof` exposure

- Check for `/debug/pprof/` unauthenticated access with a single request. If more evidence is needed, prefer `/debug/pprof/goroutine?debug=1` over heap/profile/trace on production.
- Never collect or publish heap contents that may include tokens, SQL strings, request bodies, or tenant data. Redact runtime excerpts to route names and proof of unauthenticated access.
- If testing CPU profiling is authorized, keep `seconds` small and perform it only on a lab clone.

## Reporting heuristics

- Lead with the crossed boundary: unauthenticated user to server-side fetch and reflected body, static route to sibling filesystem tree, verified upstream identity to different upstream account link, WebAuthn policy to accepted credential parameters, revocation timestamp to introspection state, disabled feature flag to versioned Account API route, same-realm UMA client to another Resource Server's resource, UMA-owning user to unrelated account profile lookup, low-privilege Flowise user to vector-store CRUD, or anonymous HTTP client to debug runtime state.
- Include exact versions and route shapes. These advisories are highly preconditioned; versionless reports will be weak.
- Use canaries instead of secrets. The wiki proof standard is controlled callback/marker evidence, not extraction of internal service data, filesystem secrets, vector-store documents, or heap tokens.
- Where an item is mainly availability-oriented, keep it secondary unless paired with a confidentiality or authorization boundary.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub Security Blog, CISA KEV, and GitHub advisory published/updated feeds. The GitHub Security Blog secret-scanning article was not promoted because it did not add a replayable offensive operator workflow for this wiki. Boxlite host-write and read-only mount advisories were updated in the feed but already covered in the existing [Boxlite, containerd, Twig, and token-boundary batch](2026-05-21-boxlite-containerd-twig-and-token-boundary-batch-ghsa.md). Bugsink tag DoS, Tomcat availability updates, proxy DoS, wangEditor/Survey Creator XSS, OpenEXR resource exhaustion, Dulwich resource/formatting issues, and BoxLite timeout bypass were tracked but not promoted because they were availability-only, already covered, or lacked a clearer reusable validation boundary than the items above.
