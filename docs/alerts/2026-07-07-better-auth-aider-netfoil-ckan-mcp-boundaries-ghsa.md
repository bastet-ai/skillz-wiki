# Better Auth, Aider, netfoil, CKAN MCP, and uutils boundary checks

Source: hourly offensive-security scan, 2026-07-07. Primary entries: GitHub advisories [GHSA-pw9m-5jxm-xr6h](https://github.com/advisories/GHSA-pw9m-5jxm-xr6h), [GHSA-hchg-qm84-cj9p](https://github.com/advisories/GHSA-hchg-qm84-cj9p), [GHSA-7w7m-v5vp-w699](https://github.com/advisories/GHSA-7w7m-v5vp-w699), [GHSA-59qp-cfj3-rp64](https://github.com/advisories/GHSA-59qp-cfj3-rp64), [GHSA-g84h-j7jj-x32p](https://github.com/advisories/GHSA-g84h-j7jj-x32p), and [GHSA-fqf6-gxhh-2xhw](https://github.com/advisories/GHSA-fqf6-gxhh-2xhw).

This batch is durable because each item maps to a reusable operator boundary: OAuth refresh-token possession crossing into confidential-client sessions without a client-secret check, AI coding assistants fetching or executing from attacker-shaped inputs, DNS policy filters parsing a different question than the upstream resolver, MCP tool parameters crossing into server-originated network requests, and GNU-compatible command assumptions breaking file-write safety in trusted automation.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-pw9m-5jxm-xr6h / CVE-2026-53512 | `better-auth` legacy `oidcProvider()` and `mcp()` plugins | `refresh_token` grant accepted a matching refresh-token row and `client_id` without authenticating the confidential client's secret | Test OAuth/MCP token endpoints for grant-specific client-auth drift; prove with disposable clients and canary refresh tokens only. |
| GHSA-hchg-qm84-cj9p / CVE-2026-10177 | Aider `api_docs.py` AWS EC2 metadata fetch path | assistant-side documentation/API fetching could be steered toward metadata-style URLs | Treat AI coding assistants as local network clients during authorized reviews; use owned canary services, never real metadata endpoints. |
| GHSA-7w7m-v5vp-w699 / CVE-2026-10175 | Aider Architect Mode `editor_coder.run` path | model/user-shaped architect-mode data crossed into code execution behavior | Validate prompt-to-tool execution boundaries with inert marker commands in disposable repos only. |
| GHSA-59qp-cfj3-rp64 | `netfoil` domain filtering | filter decision could inspect the first DNS question while a second question reached a remote DoH resolver | Add multi-question DNS packets to resolver/filter bypass harnesses; record first-question decision and upstream query evidence. |
| GHSA-g84h-j7jj-x32p / CVE-2026-53509 | `@aborruso/ckan-mcp-server` `server_url` / `base_url` tools | MCP caller-controlled CKAN URLs filtered only hostname strings, missing loopback aliases such as `ip6-localhost` | Test MCP SSRF filters with hostname aliases, DNS rebinding, and canonical address resolution using owned callbacks and lab canaries. |
| GHSA-fqf6-gxhh-2xhw | `uutils` `cp` / `install` / `mv` / `ln` backup controls | `--suffix` alone did not enable GNU-style backup mode before overwrite | In build/deploy harnesses, compare replacement coreutils behavior against GNU semantics before relying on backup or rollback flags. |

## Operator triage

1. **Split OAuth grant paths.** Do not assume `authorization_code`, device, MCP, and refresh-token grants enforce the same client authentication. Test each endpoint and plugin path independently.
2. **Model attacker prerequisites.** A refresh-token replay finding needs a realistic token-observation path in scope, such as a lab database read, log sink, browser storage capture, or compromised client. Do not collect real user refresh tokens.
3. **Treat agent tools as privileged clients.** API-doc fetchers, code editors, architect modes, and MCP tools often run with local filesystem, network, repository, and credential context that exceeds the web user who supplied the input.
4. **Compare parser layers.** DNS and URL filters fail when the policy parser and the upstream component disagree. Capture raw input, local parse result, canonical host/address, outbound request, and final callback.
5. **Keep automation-divergence findings bounded.** For `uutils`, prove behavior with temporary files and dry-run wrappers. The evidence is a compatibility mismatch that can defeat operator assumptions, not a request to destroy data.

## Replayable validation boundaries

### OAuth/MCP refresh-token confidential-client checks

- Build a disposable application using `better-auth` with the legacy `oidcProvider()` or `mcp()` plugin enabled and a confidential client registered.
- Mint a canary refresh token for a test user and client. Store no production identities or tokens in evidence.
- Replay the refresh-token grant while omitting the confidential client's secret or supplying a known-wrong secret.
- Positive evidence is a token response tied to the canary user/client despite failed client authentication. Negative controls should include a patched version and the replacement `@better-auth/oauth-provider` path when feasible.
- Report the exact grant endpoint, plugin, client type, client-auth material supplied, token subject, and patch/version state.

### AI coding assistant SSRF and execution channels

- Use a disposable repository, a lab Aider instance, and an owned HTTP callback service. Do not target `169.254.169.254`, cloud metadata services, local admin panels, or production private networks.
- For documentation/API-fetch paths, submit only owned callback URLs plus harmless path markers. Positive evidence is a server-side callback containing the expected marker.
- For Architect Mode or `editor_coder.run`-style execution paths, use inert marker commands such as writing a file under a temporary lab directory. Do not run shells, reverse connections, credential reads, package installs, or destructive file operations.
- Capture prompt/input, tool route, generated command or request, marker output, version, and whether operator confirmation was required.

### DNS multi-question filter bypass

- Build a local DNS/DoH lab with a policy that should allow `allowed.example` and block `blocked.example`.
- Send a raw DNS packet containing multiple questions where the first question is allowed and a later question is blocked. Use a controlled resolver that supports multi-question handling.
- Record whether the filter makes the decision from the first question only and whether the upstream resolver receives or answers the later question.
- Keep domains under owned zones or local lab zones. Do not use this pattern to bypass production egress controls without explicit authorization.

### MCP URL-to-network SSRF filters

- Inventory MCP tools that accept `base_url`, `server_url`, endpoint, callback, or datasource URL parameters.
- Exercise host representations through a lab callback service: canonical hostname, `localhost`, `127.0.0.1`, `[::1]`, `ip6-localhost`, mixed-case hosts, trailing dots, userinfo, punycode, and DNS-rebinding names you control.
- Positive evidence is a callback or controlled lab response from a representation that policy intended to block.
- If the tool expects CKAN-shaped responses, use a fake CKAN fixture with only synthetic package names and IDs.

### Replacement-coreutils safety checks

- In a disposable directory, compare GNU coreutils and the replacement tool with the same `cp`, `install`, `mv`, or `ln` invocation using `--suffix` alone.
- Capture pre/post file lists and checksums for canary files only.
- Use the result to decide whether exploit-build, deployment, backup, or rollback scripts can trust GNU compatibility assumptions in the target environment.

## Reporting notes

- Name the crossed boundary precisely: **refresh-token possession to confidential-client session**, **agent URL fetch to local/private network**, **prompt/tool input to editor execution**, **first DNS question to later-question resolver behavior**, **MCP URL parameter to server-originated network request**, or **GNU compatibility flag to unsafe overwrite**.
- Include versions, plugin enablement, client type, raw packet or URL forms, canonicalization output, callback proof, and negative controls.
- Keep proofs to canary tokens, lab repositories, owned callback hosts, local DNS zones, fake CKAN data, and temporary files.

## July 7 follow-up: Better Auth identity and OAuth provider boundary wave

Additional Better Auth advisories published later in the same GitHub advisory wave. These belong with the existing Better Auth batch because they expose related identity-provider, OAuth, SCIM, and organization-plugin boundaries rather than a separate product workflow.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-j8v8-g9cx-5qf4](https://github.com/advisories/GHSA-j8v8-g9cx-5qf4) | `@better-auth/scim` non-organization providers | SCIM provider rows are not bound to the creating user unless provider ownership is explicitly enabled | Test tenant/provider management APIs for missing owner binding, token regeneration, and cross-user provider deletion with two disposable users. |
| [GHSA-2vg6-77g8-24mp](https://github.com/advisories/GHSA-2vg6-77g8-24mp) | Better Auth admin, anonymous, and SCIM user-deletion flows with secondary session storage | user deletion does not always invalidate cached secondary-storage sessions | Validate stale-session authority after account deletion only with your own test users and synthetic session markers. |
| [GHSA-7w99-5wm4-3g79](https://github.com/advisories/GHSA-7w99-5wm4-3g79) / CVE-2026-53518 | `@better-auth/oauth-provider` and legacy OAuth/MCP token endpoints | authorization-code redemption uses a non-atomic find-then-delete primitive | Add concurrent single-use-code redemption to OAuth/MCP token endpoint tests; prove duplicate token minting with canary clients only. |
| [GHSA-5rr4-8452-hf4v](https://github.com/advisories/GHSA-5rr4-8452-hf4v) / CVE-2026-53513 | `@better-auth/sso` provider registration and update | authenticated users can persist unvalidated OIDC token, userinfo, and JWKS endpoints when `skipDiscovery` is used | Test SSO self-service registration for stored SSRF and IdP endpoint trust drift using owned callbacks and fake IdP fixtures. |
| [GHSA-392p-2q2v-4372](https://github.com/advisories/GHSA-392p-2q2v-4372) / CVE-2026-53517 | OAuth refresh-token grant with `offline_access` | concurrent refresh-token redemption can fork a token family before revocation state is visible | Test refresh-token rotation as a race condition, not only as a sequential replay. |
| [GHSA-9h47-pqcx-hjr4](https://github.com/advisories/GHSA-9h47-pqcx-hjr4) | legacy `oidcProvider()` and `mcp()` discovery / authorize paths | discovery advertises `alg=none` and runtime accepts or downgrades to plain PKCE by default | Add metadata-to-client algorithm negotiation and PKCE downgrade checks to OIDC/MCP provider reviews. |
| [GHSA-86j7-9j95-vpqj](https://github.com/advisories/GHSA-86j7-9j95-vpqj) | legacy `oidc-provider` / `mcp` client registration plus consent UI | `javascript:` redirect URIs can be stored and later handed to client-side consent navigation code | Test dynamic OAuth client registration and consent-page navigation sinks with harmless DOM markers, not credential theft. |
| [GHSA-g38m-r43w-p2q7](https://github.com/advisories/GHSA-g38m-r43w-p2q7) / CVE-2026-53516 | email/password plus OAuth or SSO implicit account linking | pre-registered unverified local email can be linked to a later verified OAuth identity | Reproduce pre-account-hijacking flows with owned mailboxes and two disposable identities. |
| [GHSA-fmh4-wcc4-5jm3](https://github.com/advisories/GHSA-fmh4-wcc4-5jm3) / CVE-2026-53514 | organization invitation acceptance | invitation recipient checks rely on email-string equality without requiring verified mailbox ownership | Test invitation acceptance with disposable orgs, roles, and owned addresses; do not target real invite links. |
| [GHSA-p2fr-6hmx-4528](https://github.com/advisories/GHSA-p2fr-6hmx-4528) | `@better-auth/oauth-provider` RFC 8707 `resource` handling | token endpoint lets clients choose an allow-listed audience not bound to the authorization grant or refresh token | Test multi-resource OAuth servers for audience/resource swapping across authorization and refresh grants. |

### Follow-up operator checks

1. **SCIM provider ownership.** Create two disposable users. User A creates a non-organization SCIM provider. User B attempts only metadata read, connection list, token regeneration, and deletion actions against User A's provider ID. Positive evidence is cross-user control of the provider or bearer token lifecycle; negative evidence is an owner-bound denial.
2. **Deletion to stale-session authority.** With secondary storage configured in a lab, sign in as a disposable user, delete that user through each enabled admin, anonymous, or SCIM path, then replay the pre-delete session token against a harmless profile/status endpoint. Stop at proof of continued authority; do not access production accounts or data.
3. **OAuth one-time secret races.** For authorization codes and refresh tokens, fire two same-code or same-refresh-token requests in parallel against a disposable client. Positive evidence is more than one access/refresh token minted from a supposedly single-use credential. Include timing, token family IDs if available, and patched behavior.
4. **Self-service SSO endpoint control.** Register or update a fake OIDC provider with owned callback URLs for token, userinfo, and JWKS endpoints. Positive evidence is a server-side fetch or reflected synthetic profile body from an endpoint the user should not be able to steer. Never use cloud metadata, internal admin panels, or real IdPs.
5. **OIDC/MCP metadata and PKCE downgrade.** Fetch discovery metadata, record supported signing algorithms and PKCE methods, then attempt only canary flows for `alg=none` negotiation or `code_challenge_method=plain` acceptance. Keep relying-party tokens synthetic and do not forge real sessions.
6. **Consent redirect URI sink.** If dynamic registration is enabled, register a disposable OAuth client with a harmless `javascript:` or marker redirect URI and exercise only the consent UI path. Positive evidence is the marker reaching a browser navigation sink; do not run credential-stealing script.
7. **Pre-account and invitation hijack flows.** Use owned email aliases. Pre-register the target alias as an unverified local account, then complete a legitimate OAuth/SSO login or organization invite for the same alias. Positive evidence is identity or role attachment to the pre-created account without mailbox verification.
8. **Resource indicator binding.** In a lab with at least two valid audiences, authorize for one resource and redeem the code or refresh token for another allow-listed resource. Positive evidence is an access token whose `aud` or resource claim was not covered by the authorization grant.

### Follow-up reporting notes

- Lead with the precise crossed boundary: **provider ID to ownerless SCIM control**, **deleted user to cached session**, **single-use OAuth credential to duplicate mint**, **self-service SSO endpoint to server fetch**, **discovery metadata to unsafe algorithm**, **client redirect URI to consent-page script sink**, **unverified email to OAuth/organization identity**, or **token endpoint resource to unauthorized audience**.
- Strong evidence includes plugin enablement, Better Auth package/version, route, client type, role, exact grant or endpoint, race timing, synthetic token/session identifiers, before/after ownership or role state, and negative controls.
- Keep artifacts synthetic: disposable users, owned domains, fake IdPs/JWKS, canary OAuth clients, test orgs, harmless browser markers, and redacted token prefixes only.

## July 20 follow-up: SSO provider creation role drift

[GHSA-gv74-j8m3-fg5f](https://github.com/advisories/GHSA-gv74-j8m3-fg5f) / CVE-2026-53515 extends the Better Auth organization/SSO checks with a create-versus-manage authorization differential. In affected `@better-auth/sso` versions `>=1.2.10,<1.6.11`, `POST /sso/register` can accept any organization member when SSO and organization plugins are enabled, while companion read, update, and delete paths require an owner or admin. A regular member can therefore attach an attacker-controlled OIDC or SAML provider to an organization; downstream SSO provisioning determines whether this stops at unauthorized configuration, adds members, or reaches a configured admin role.

### Two-role provider lifecycle matrix

1. Create a disposable organization with one owner and one ordinary member. Enable the same `providersLimit`, domain-verification, and organization-provisioning settings as the target fixture.
2. Host a minimal fake OIDC or SAML provider on an owned origin. Use only synthetic subject, email, and group claims.
3. As the member, attempt create, list, get, update, and delete operations for an organization-linked provider. Record route, role, organization ID, status, and whether a provider row changed.
4. If registration succeeds, perform one callback with a disposable identity and record only the resulting synthetic membership and role. Do not reuse a real IdP, domain, assertion, or employee identity.
5. Repeat as owner/admin, on `@better-auth/sso@1.6.11` or later, and with `providersLimit: 0` as negative controls.

Strong evidence shows **ordinary organization membership -> SSO provider create succeeds -> companion lifecycle operations remain admin-gated -> synthetic callback provisions a canary identity**. State the configured default/get-role behavior; do not claim admin creation when the lab only demonstrates member provisioning.

## July 24 follow-up: passwordless pre-account, billing target, and SCIM namespace boundaries

Three later advisories extend the identity checks on this page:

| Advisory | Preconditions | Failed binding | Bounded operator proof |
| --- | --- | --- | --- |
| [GHSA-qq9h-g4jm-xgf3](https://github.com/advisories/GHSA-qq9h-g4jm-xgf3) | open email/password registration plus magic-link or email-OTP sign-in | mailbox proof verifies a pre-created account without removing its attacker-planted password | owned email alias, disposable account, and post-verification password/session decision table |
| [GHSA-h3rm-78g3-j7cp](https://github.com/advisories/GHSA-h3rm-78g3-j7cp) | `@better-auth/stripe`, organization subscriptions, `authorizeReference`, and membership in multiple orgs | middleware authorizes the query/body org ID while the handler falls back to the session's active org | two synthetic orgs, fake billing objects, and cancel/change/restore/portal target recorder |
| [GHSA-rjg6-39jm-rgg4](https://github.com/advisories/GHSA-rjg6-39jm-rgg4) | `@better-auth/scim`; collision impact also needs another provider using the selected ID | token-controlled SCIM provider ID aliases an SSO/OIDC/social account namespace; deactivation/email updates also drift from identity state | synthetic provider IDs, two lab users, marker-only profile/session state, and no real IdP data |

### Passwordless pre-account matrix

This is the passwordless sibling of the OAuth pre-account check above. Use an owned mailbox alias throughout:

1. Enable open email/password registration and either the magic-link or email-OTP plugin in a disposable app.
2. Register the alias with a canary password but leave the email unverified. Confirm the account cannot yet reach a harmless authenticated marker route.
3. Complete the legitimate magic-link or email-OTP flow for the same alias as the mailbox owner.
4. In separate sessions, test the newly issued passwordless session, the pre-verification canary password, and any session created before verification.
5. Repeat for both passwordless plugins that the target enables, then on `better-auth@1.6.22` or `1.7.0-beta.10` or later.

Positive evidence is **attacker-precreated unverified account -> mailbox owner verifies through a passwordless flow -> planted password remains authoritative**. Stop at your own profile/status marker. Do not access victim data or test with an address you do not control.

### Stripe organization target-confusion matrix

Create organizations `ORG-ALPHA` and `ORG-BETA`. Give the same disposable user billing authority in Alpha but ordinary membership in Beta; make Beta the active organization. Back the Stripe integration with a mock or test-mode recorder containing synthetic subscriptions only.

For cancel, change-plan, restore, and billing-portal actions, vary the organization selector independently:

| Query org | Body org | Active org | Authorization should cover | Handler actually targets |
| --- | --- | --- | --- | --- |
| Alpha | absent | Beta | Alpha | record and compare |
| absent | Alpha | Beta | Alpha | record and compare |
| Alpha | Beta | Beta | one unambiguous rejected target | record and compare |

Do not cancel or expose real subscriptions. A mock handler that records `subscription.referenceId`, or Stripe test mode with throwaway customers and no payment method, is sufficient. Strong evidence proves **approved org ID from middleware -> different active/body org selected by handler -> synthetic billing action crosses the intended org role boundary**. The documented target remains an organization the caller belongs to; do not call this arbitrary-tenant access.

### SCIM provider-ID collision and lifecycle checks

1. In a lab, configure a fake OIDC/SSO provider with a distinctive provider ID and provision only synthetic users.
2. As a low-privileged authenticated user allowed to generate SCIM tokens, request a SCIM provider/token using the same ID.
3. With that token, attempt only list/get and marker-only PATCH operations against the synthetic identity. If deletion is in scope, use a disposable user whose sole purpose is this fixture and record whether the global user or only a SCIM link is removed.
4. Separately test `active: false`: record HTTP success, disabled state, session revocation, and subsequent access to a harmless status route.
5. Separately change one disposable user's email to another owned alias. Record uniqueness handling and whether `emailVerified` remains true after reassignment.
6. Repeat on `@better-auth/scim@1.6.22` or `1.7.0-beta.10` or later. Token creation should reject collisions, and lifecycle changes should remain bound to SCIM-owned identities.

Treat these as three results, not one oversized claim: **provider namespace collision to unrelated account selection**, **deactivation signal to stale access**, and **email reassignment to stale verification proof**. Keep bearer tokens redacted and never enumerate real SSO/social identities, delete production users, or collect profile data.

## July 29 follow-up: netfoil blocked-name loopback routing

[GHSA-xvg2-cgv6-6h7v](https://github.com/advisories/GHSA-xvg2-cgv6-6h7v) adds a distinct DNS-policy edge to the multi-question check above. Before 0.4.0, netfoil answered blocked names with `0.0.0.0`; on its target Linux platform, clients can interpret that address as the local host. A request that policy intended to discard can therefore reach a listener in the client's own network namespace.

Extend the local DNS harness with one blocked canary name and a harmless HTTP recorder bound only inside the disposable client namespace. Capture the DNS question, block decision, returned RCODE/address, client socket destination, Host header, and recorder hit. Compare NXDOMAIN, `0.0.0.0`, `127.0.0.1`, and a normal allowed answer, then repeat on netfoil 0.4.0. Positive evidence is **blocked name -> synthetic `0.0.0.0` answer -> client connects to the local canary service**. Do not probe real local admin services or infer cross-host access from this client-local routing behavior.

## August 2 Better Auth path and passkey-object follow-up

Two later advisories add route-normalization and object-ownership checks to the Better Auth harness:

- [GHSA-9fq7-6g6p-g9rm](https://github.com/advisories/GHSA-9fq7-6g6p-g9rm) / CVE-2025-71399: before `1.4.5`, the bundled `rou3` router collapses empty path segments. A request such as `/path`, `//path`, or `///path` can reach the same handler while `disabledPaths` or path-keyed rate limits evaluate a different raw representation. This depends on the edge proxy preserving repeated slashes.
- [GHSA-44ff-3cmc-mgqf](https://github.com/advisories/GHSA-44ff-3cmc-mgqf) / CVE-2025-71400: passkey deletion before `1.4.0` accepts a caller-selected passkey ID without binding it to the authenticated user.

### Raw-path versus selected-route matrix

1. Use a disposable Better Auth app behind both a direct listener and the same proxy family used by the target. Configure one harmless route in `disabledPaths` and one route with a low canary rate limit.
2. Send the ordinary path plus repeated-slash forms. Capture the client request target, proxy-forwarded target, policy lookup key, router-normalized path, selected handler, and rate-limit bucket.
3. A positive disabled-path result is **policy sees a non-disabled raw path -> router collapses empty segments -> disabled handler runs**. A positive rate-limit result is multiple raw spellings reaching one handler while consuming separate policy buckets.
4. Repeat on `1.4.5` and with a proxy that deliberately collapses repeated slashes. Report the deployment precondition instead of claiming a universal bypass.

### Passkey ownership matrix

1. Create users A and B and register one synthetic passkey for each using a lab authenticator. Record opaque IDs only in the private test artifact.
2. As A, issue delete requests for A's ID, B's ID, an unknown ID, and a malformed ID. Replace the deletion sink with a recorder first; if a real deletion is necessary, delete only B's disposable canary passkey.
3. Record authenticated subject, selected passkey ID, resolved owner, authorization decision, and side effect. Repeat on `1.4.0`.

Report **authenticated user A -> caller-selected passkey ID for B -> deletion sink without owner check**. Do not enumerate passkey IDs, remove a real authentication factor, or interpret route reachability as deletion without before/after canary evidence.

## September 4 follow-up: CKAN MCP server cache-key, error-verbose, and allowlist boundaries

Three later CKAN MCP Server advisories add reusable MCP server-trust checks to the July 7 `server_url`/`base_url` SSRF filter work above. They belong on this page because they are the same product boundary: caller-controlled MCP parameters crossing into cache, error, and allowlist logic that a CKAN MCP server exposes.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-78x9-fhhx-v2g6](https://github.com/advisories/GHSA-78x9-fhhx-v2g6) / CVE-2026-73846 | CKAN MCP Server cache-key canonicalization | a cache-key collision lets one request's cached response answer a different request (cache confusion / poisoning) | Test MCP/HTTP cache keys for canonicalization collisions between attacker-shaped and legitimate requests; prove with two synthetic requests that map to one key. |
| [GHSA-83x6-42hr-jc76](https://github.com/advisories/GHSA-83x6-42hr-jc76) / CVE-2026-73845 | MQA server allowlist | an unanchored allowlist regex/prefix matches attacker hosts or subpaths | Test the allowlist pattern with anchored vs. prefix/substring forms; record which attacker host passes. |
| [GHSA-6f9w-9hf2-5rg3](https://github.com/advisories/GHSA-6f9w-9hf2-5rg3) / CVE-2026-73844 | verbose error responses | an error path discloses internal details (stack, config, data) it should not | Trigger the error path with a malformed request and capture the disclosed fields; redact and report the disclosure surface. |

### Cache-key canonicalization collision

1. Identify the MCP server's request cache and how it builds the cache key (URL, method, selected params, auth-independent fields).
2. Craft two synthetic requests that differ in an attacker-controlled field but canonicalize to the **same** cache key — e.g., differing query param order, encoding, or a parameter the key omits.
3. Seed request A with a marker response, then issue request B. A positive is B receiving A's cached marker despite the differing field. Report the two raw requests and the shared key; do not poison a shared production cache.

### Unanchored allowlist match

1. Locate the allowlist that gates which CKAN/MQA hosts or paths are permitted.
2. Test attacker forms against it: the allow value as a **prefix** of an attacker host (`example.com.attacker.tld`), as a **substring**, with appended path, and with encoding. A positive is an attacker host/ path passing the unanchored check.
3. Negative control: the anchored/regex-anchored version of the same allowlist.

### Verbose error disclosure

1. Send a malformed or out-of-bounds request that forces the error path.
2. Capture the response body and record which fields are disclosed (stack frames, internal URLs, config keys, data fragments). Redact real secrets and report the disclosure surface and the request shape that triggered it.

Keep all three to synthetic CKAN fixtures, owned/lab peers, and redacted output; do not read real CKAN data or poison a live shared cache.

## September 22 follow-up: the guard validates the string, the client connects to the address

[GHSA-798p-78g2-v556](https://github.com/advisories/GHSA-798p-78g2-v556) / CVE-2026-61612: `@aborruso/ckan-mcp-server` SSRF guard `validateServerUrl` — patched **three times** now (CVE-2026-33060 added the guard, CVE-2026-53509 added `ip6-localhost`/`ip6-loopback` alias strings) — still validates only the **hostname string** (denylist + IPv4-literal regex) and never resolves DNS. A `server_url` whose hostname *resolves* to `127.0.0.1`, `169.254.169.254`, or RFC-1918 passes the guard, and this time the impact crosses from loopback to **IMDS** — strictly more than the prior CVE. Unpatched as of current latest 0.4.107; the self-hosted unauthenticated HTTP transport (`TRANSPORT=http`, `POST /mcp`) is the reachable surface (the Cloudflare Worker deployment is platform-sandboxed).

Reusable axes:

1. **String-validation-vs-resolution gap is the permanent SSRF-guard finding class.** When you find a URL guard, ask which representation it checks and which the HTTP client actually uses: denylisted literal, resolved A/AAAA record, redirect target, or proxy-selected address. If validation and connection touch different representations, the guard is bypassable by DNS alone — no rebinding TTL tricks needed, just an A record pointing at a blocked address.
2. **Fix-history is a target map.** Three CVEs on one guard with each fix only appending denylist strings means the root cause was never addressed. When an advisory reads "incomplete fix of CVE-X", read CVE-X and its predecessor first — the prior fix diffs tell you exactly which representations are covered and which were never considered.
3. **Transport decides severity.** Same package, same guard: the hosted Worker endpoint can't reach loopback/IMDS while the self-hosted HTTP transport reaches it directly from any remote client. Record the deployment mode before scoring or reporting.

Bounded proof (lab only): stand up a disposable instance of the MCP server with `TRANSPORT=http`, point `server_url` at an owned domain whose A record you set to a loopback-bound canary HTTP listener (never real cloud IMDS), and capture the server-side callback as evidence the resolved address passed the string guard. Negative control: the IPv4-literal form the denylist does block.
