# Identity-assertion, MCP-metadata, and client-render late-wave boundaries: Prowler SAML tenant claim, ZITADEL auto-link/JWT replay, Okta SDK response race, Doris MCP SQLi, JSON:API `__proto__`, SiYuan Bazaar XSS, Mattermost + NiFi authorization drift (18 GHSAs)

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-09-16 (late/updated waves published 2026-09-11T21:31Z–2026-09-14T18:14Z, surfaced via the updated-advisories feed).

One shared axis across this cluster: **an authority decision trusts an attacker-influenced value — an asserted email domain, an unverified IdP email claim, a response object from the wrong request, a database name inside a metadata query, an object `type` used as a lookup key, marketplace package metadata rendered as HTML, or a slash-command handler that skipped the admin check.** Each is independently testable with synthetic principals and denied final sinks.

## Advisory table

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-h8m9-jgf8-vwvp](https://github.com/advisories/GHSA-h8m9-jgf8-vwvp) | CVE-2026-59151 | critical (9.6) | Prowler < 5.30.3: SAML ACS finish logic **re-derives the tenant from the asserted email domain** (`user.email.split("@")[-1]` → `SAMLConfiguration.get(email_domain=...)`) instead of the validated SAML configuration that selected the ACS route. A malicious tenant with its own IdP completes a valid SAML flow for its configured domain while asserting an address from a victim tenant's domain, and receives a token for the wrong tenant — cross-tenant account takeover. |
| [GHSA-992q-9gwp-7r79](https://github.com/advisories/GHSA-992q-9gwp-7r79) | — | high | ZITADEL: account auto-linking by email **does not check whether the external IdP actually verified that email address**. An identity provider that allows self-asserted or unverified addresses can link into (and take over) an existing local account with the same address. |
| [GHSA-v77h-2w3m-94hx](https://github.com/advisories/GHSA-v77h-2w3m-94hx) | — | medium | ZITADEL JWT IdP provider: `exp` not validated on IdP assertions → captured JWT assertions are replayable indefinitely (folded here from the Sept 15 wave's adjacent list). |
| [GHSA-j5gq-897m-2rff](https://github.com/advisories/GHSA-j5gq-897m-2rff) | — | high (8.4) | Okta Java SDK 11.0.0–20.0.0: `ApiClient` race condition under concurrency lets a status code or response header from **one request leak into another request's response**. When applications branch access-control decisions on response status, a concurrent-request adversary can steer authorization outcomes. Fixed in 21.0.0. |
| [GHSA-pqrj-4gwg-h5f7](https://github.com/advisories/GHSA-pqrj-4gwg-h5f7) | CVE-2025-66336 | high (8.1) | Apache Doris MCP Server < 0.6.1: user-controlled database name interpolated directly into a metadata SQL query, executed **without passing the caller's authorization context** → SQL injection plus auth-context loss on metadata scope. An MCP metadata tool is still a SQL sink. |
| [GHSA-325j-mg25-8q58](https://github.com/advisories/GHSA-325j-mg25-8q58) | — | critical (9.1) | yayson JSON:API client ≤ 4.2.0: internal lookup tables are plain objects keyed by document `type`/`id` → a document with `type: "__proto__"` writes model objects onto `Object.prototype` (attacker-controlled key **and** value, process-lifetime persistence). The malicious type can arrive through an `included` resource referenced by a relationship, **bypassing any `data.type` allow-list**. |
| [GHSA-v3mg-9v85-fcm7](https://github.com/advisories/GHSA-v3mg-9v85-fcm7) (+ [duplicate GHSA-24r3-p3x6-cqvx](https://github.com/advisories/GHSA-24r3-p3x6-cqvx)) | CVE-2026-56397 | medium | SiYuan ≤ 3.5.9 Bazaar marketplace: package `displayName`/`description` injected into the Bazaar page via template literals with **no HTML escaping (zero-click)**; README rendered with `lute.New()` without `SetSanitize(true)` (one-click). Executes in Electron with `nodeIntegration: true` / `contextIsolation: false` → OS command execution from browsing a package marketplace. |
| [GHSA-jqgv-39mg-7c2r](https://github.com/advisories/GHSA-jqgv-39mg-7c2r) | — | medium | Mattermost ≤ 11.7.0/10.11.17: `/ac/installed` (Atlassian Connect install callback) is **unauthenticated** — a remote attacker can inject a rogue `sharedSecret` during the pending-install window. |
| [GHSA-2g8v-grq3-hq2g](https://github.com/advisories/GHSA-2g8v-grq3-hq2g) | — | medium | Mattermost: the `/gitlab connect <instance>` slash command calls `setDefaultInstance` with **no administrator authorization** → any authenticated user overwrites the global default GitLab instance configuration. |
| [GHSA-mxq2-5jpg-7474](https://github.com/advisories/GHSA-mxq2-5jpg-7474) | — | medium | Mattermost: subscription edit `PUT` does not validate channel ownership of the existing subscription → authenticated user hijacks subscriptions in channels they cannot see. |
| [GHSA-g5vr-6pgg-74qv](https://github.com/advisories/GHSA-g5vr-6pgg-74qv) | — | low | Mattermost: `PUT /api/v4/users/{id}/active` skips the bot-specific Integrations permission → User-Manager-role users can deactivate bot accounts. |
| [GHSA-h998-hxxj-8q83](https://github.com/advisories/GHSA-h998-hxxj-8q83) | — | medium | Mattermost: global session revocation does not invalidate cached auth state on **already-open WebSocket connections** → revoked users keep receiving real-time events until reconnect. |
| [GHSA-chxj-gxww-q98w](https://github.com/advisories/GHSA-chxj-gxww-q98w) | — | high (7.2) | Apache NiFi 1.2.0–2.9.0 CaptureChangeMySQL: table names not properly escaped → SQL command injection through crafted table naming; the 1.8.0 quoting patch narrowed but did not close the identifier-escaping surface. |
| [GHSA-8vm2-c32j-mvfr](https://github.com/advisories/GHSA-8vm2-c32j-mvfr) | — | medium | Apache NiFi 0.0.1–2.9.0: qualified URL construction trusts `X-ProxyHost` / `X-Forwarded-Host` values; the 1.6.0 Host-header restriction property was **never applied to the alternate proxy headers** → attacker-steered redirect/data-reference URLs. |
| [GHSA-r2g5-993q-664g](https://github.com/advisories/GHSA-r2g5-993q-664g) | — | medium | Apache NiFi 1.12.0–2.9.0: replacing Process Groups skips the `@Restricted` authorization check → general-write users can add components that require elevated privileges. |
| [GHSA-qvj8-gwpm-4x49](https://github.com/advisories/GHSA-qvj8-gwpm-4x49) | — | medium | Apache NiFi 1.15.0–2.9.0: **read-only** users can submit configuration-verification requests with proposed property overrides → predefined verification methods run with settings the user could never save. |

## Why this is worth an operator page

- **"Tenant/authority from asserted attribute" is the recurring SAML/SSO design flaw.** Prowler validated the SAML signature but then picked the *victim's* tenant by string-splitting the asserted email. Test every IdP-backed multi-tenant app by asking: after all crypto checks pass, what value selects the account/tenant/role? If it is anything inside the assertion (email domain, subject, group name) rather than the configuration that authenticated the flow, you have cross-tenant ATO. Pairs directly with the [Sept 16 identity-provider page](2026-09-16-zitadel-keycloak-nezha-identity-provider-authority-boundaries-ghsa.md): provenance checks protect *who exchanged*; binding checks protect *where the token lands*.
- **Auto-linking by email turns every IdP into an ATO oracle if verification is not enforced on the IdP side.** Any "we found an account with this email, linking it" flow must require the IdP to assert verified=true — and must be tested against a fake IdP that self-asserts arbitrary addresses unverified.
- **Response-object confusion is a new-looking, testable axis** (Okta SDK): where a client library shares one mutable response slot across threads, an attacker racing requests can make decision code see the wrong status. Look for `if (response.status == 403) deny` patterns in multithreaded consumers.
- **MCP servers make metadata queries the soft SQL target.** The Doris record combines two misses — string interpolation of an identifier and dropping the caller's auth context on the metadata path. Audit every MCP tool that maps a user parameter to `SHOW`/`information_schema`-style queries separately from the "real" query tools.
- **JSON:API clients parse attacker-controlled *structure*, not just values.** `type`/`id` become object keys before any validation; `__proto__` survives `JSON.parse`, and `included` relationships bypass top-level type allow-lists. Any JS library keying plain objects on document fields inherits this.
- **Marketplace metadata is zero-click input into trusted UI renderers.** SiYuan's Bazaar renders package name/description/README into an Electron renderer with node integration — package-catalog XSS-to-RCE is the desktop-app supply-chain pattern, same axis as the wiki's existing Bazaar README/XSS entries.
- **Slash-command and callback handlers are the least-audited authorization surface** (Mattermost trio): command handlers, install-callback endpoints, and subscription-edit routes each skipped exactly one check (admin, authentication, ownership) that the "main" API surface enforces. Enumerate command/callback/subscription route families with a low-privilege canary user.
- **NiFi's four records repeat the wiki's alternate-header and read-path-write axes**: Host validation that never reached `X-Forwarded-Host`, identifier escaping that only narrowed injection, a replace-flow that skipped the restricted-component check, and a read-only role holding a "validate with proposed config" write primitive. Verification endpoints are write paths.

## Validation workflows (authorized scope only)

!!! warning "Synthetic IdPs, tenants, packages, and lab instances only"
    Run every proof against lab deployments you own with fake IdPs, disposable tenants/users, synthetic packages with harmless markers, and denied final sinks. Never mint tokens into real tenants, never link real email identities, never install executable marketplace packages, never run SQL beyond inert canaries.

### 1. SAML tenant-binding decision table (Prowler-style)

Preconditions: lab multi-tenant SaaS with SAML, two disposable tenants (A yours, B victim-role) each with a controllable IdP, and two canary users.

1. Configure tenant A's SAML for a domain you own; note that tenant B's domain is separately configured.
2. Complete a valid SAML flow through A's ACS route while asserting an email address in B's domain.
3. Record the decision table: which tenant the issued token belongs to, which memberships were touched, and whether the token's tenant came from the validated configuration or the asserted email domain.
4. Positive: token issued for tenant B (or B memberships mutated) from a flow validated against A's configuration. Report as **validated configuration ≠ issuance tenant** with the exact assertion fields redacted.

### 2. Auto-link and assertion-replay checks (ZITADEL-style)

1. Stand up a fake IdP that issues assertions for arbitrary addresses **without** a verified-email claim (or with verified=false).
2. Attempt login → observe whether an existing local account with the matching address is auto-linked to the fake identity. Positive: link succeeds with no verification.
3. Separately, capture a valid IdP JWT assertion on the lab and replay it after its `exp` window; positive = acceptance (fold with the token-exchange matrix on the Sept 16 identity page).

### 3. MCP metadata-query audit

1. For any MCP database server, list tools whose arguments select databases/tables/schemas (metadata tools) as a separate family from data-query tools.
2. Pass an inert quote/paren/`information_schema`-fragment canary as the identifier and observe generated SQL via lab query logging — prove identifier-to-SQL-syntax crossing, not data exfiltration.
3. Compare the metadata call's backend authorization context against the data-query path (canary user with intentionally denied metadata scope; a positive is the metadata call succeeding where the same principal's query is denied).

### 4. JSON:API `__proto__` key check (yayson-style)

1. In a lab consumer, fetch/parse a synthetic document with `data.type = "__proto__"` and a marker attribute, and a second document carrying the same type inside `included` behind a `data.type` allow-list.
2. Positive: `Object.prototype` gains a marker property after parsing (check `({}).<id>`) or allow-listed-only behavior fails for `included` resources.
3. Stop at pollution detection — do not chain to app-specific gadgets or execute code.

### 5. Marketplace-metadata rendering check (SiYuan-style)

1. Serve a mocked package-catalog response with a harmless inert HTML marker (e.g., an `<img>` to an owned no-content observer, or a focus/pointer event canary) inside `displayName`/`description`/README fields.
2. Positive: the observer is hit (zero-click page load) or the marker survives to the DOM without escaping. Record whether the renderer's Electron/WebView context exposes node integration — state that as the impact ceiling, do not execute OS commands.

### 6. Command/callback/subscription route sweep (Mattermost-style)

1. With a low-privilege canary user, enumerate slash commands and integration callbacks; attempt privileged side effects (`/gitlab connect <owned-observer-instance>`, subscription edits referencing foreign channel IDs, unauthenticated `POST /ac/installed` with a fake secret).
2. Record per-route decision tables (principal → allowed/denied → side effect reached); positive = any handler whose side effect executes below its required role. Restore all mutated global config immediately.
3. For the WebSocket item: open a real-time session, trigger admin-side global session revocation from a second admin account, and record whether the open socket keeps streaming events after HTTP auth is dead — cached-auth-vs-reconnect differential.

### 7. NiFi header/verify-endpoint checks

1. Set the Host-restriction property to an allow-list, then request pages/APIs with `X-Forwarded-Host` / `X-ProxyHost` set to an owned observer domain; positive = generated qualified URLs (redirects, share links) follow the unvalidated header.
2. With a read-only user token, submit a config-verification request carrying a proposed property override pointing at an owned no-content listener; positive = the verification method executes with attacker settings.
3. Where CaptureChangeMySQL is in scope (lab MySQL + lab NiFi only), test one inert identifier canary for escaping into query structure via lab query logs; never inject live DDL/DML.

## Adjacent records processed without publication

FrontMCP/`mcp-from-openapi` [GHSA-65h7-9wrw-629c](https://github.com/advisories/GHSA-65h7-9wrw-629c) (latest-version bypass of the external-`$ref` SSRF fix via name resolution, redirects, IPv4-mapped IPv6), Mockoon admin-API [GHSA-rqx4-3f6q-3x2v](https://github.com/advisories/GHSA-rqx4-3f6q-3x2v) and Mockoon sibling-prefix [GHSA-8wqc-v2q8-vff2](https://github.com/advisories/GHSA-8wqc-v2q8-vff2), Prowler beyond the table, and the Shopper siblings were already published on the [Sept 15 MCP/agent local-surface page](2026-09-15-mcp-dns-rebinding-alternate-auth-path-and-sandbox-boundaries-ghsa.md) — the updated-feed re-surfacing is marked processed there. October CMS [GHSA-xv9m-fm3w-8w5x](https://github.com/advisories/GHSA-xv9m-fm3w-8w5x) completes the safe-mode trio already folded on the Sept 15 page: Laravel session store exposed to the Twig sandbox plus Eloquent `__call`-forwarded raw-SQL methods → arbitrary DB read and backend-session forgery, but gated on opt-in `cms.safe_mode` + untrusted markup editor + existing superuser session target (CVSS 3.3); the reusable reminder — **framework service objects reachable from template sandboxes carry their whole method surface, and `__call` forwarding hides raw SQL from method-name blocklists** — stays as a hygiene note rather than a new page. The two older October CMS scheme/deserialization legs remain folded on the Sept 15 page. Flowise `overrideConfig` [GHSA-5cph-wvm9-45gj](https://github.com/advisories/GHSA-5cph-wvm9-45gj) is a 2024 advisory with a 2026 duplicate marking the fix landed (disable/allow-list `overrideConfig`); its caller-controlled-config axis is already covered by the existing prediction-API coverage on the [Aug 4 Flowise page](2026-08-04-flowise-workspace-runtime-credential-boundaries-ghsa.md) — no new workflow. LiteLLM and Crawl4AI late-wave items were folded into their existing product pages this run.

## Reporting heuristics

- Name the exact value that carried authority: *asserted email domain → tenant*, *unverified IdP email → linked account*, *prior thread's response status → authorization branch*, *document `type` key → prototype slot*, *package metadata field → trusted-renderer HTML*, *slash-command handler → global config write*. The value, not the CVE, is the report's spine.
- For tenant/linking findings, prove with a second disposable tenant/account pair and show the issuance-side artifact (token tenant claim, membership row presence) — never real user identities.
- Keep the Mattermost/NiFi sweeps to route-family decision tables; a single denormalized handler is a complete finding — restore all lab state afterward.
- Mark the Okta-SDK item as a *library-consumer* finding: impact depends on how the integrating app branches on status codes; report the race primitive plus the consuming pattern, not a platform RCE claim.

## Sources

- GitHub Advisory Database: [GHSA-h8m9-jgf8-vwvp / CVE-2026-59151](https://github.com/advisories/GHSA-h8m9-jgf8-vwvp)
- GitHub Advisory Database: [GHSA-992q-9gwp-7r79](https://github.com/advisories/GHSA-992q-9gwp-7r79), [GHSA-v77h-2w3m-94hx](https://github.com/advisories/GHSA-v77h-2w3m-94hx)
- GitHub Advisory Database: [GHSA-j5gq-897m-2rff](https://github.com/advisories/GHSA-j5gq-897m-2rff); fix reference [okta-sdk-java 21.0.0](https://github.com/okta/okta-sdk-java/releases)
- GitHub Advisory Database: [GHSA-pqrj-4gwg-h5f7 / CVE-2025-66336](https://github.com/advisories/GHSA-pqrj-4gwg-h5f7)
- GitHub Advisory Database: [GHSA-325j-mg25-8q58](https://github.com/advisories/GHSA-325j-mg25-8q58)
- GitHub Advisory Database: [GHSA-v3mg-9v85-fcm7 / CVE-2026-56397](https://github.com/advisories/GHSA-v3mg-9v85-fcm7), duplicate [GHSA-24r3-p3x6-cqvx](https://github.com/advisories/GHSA-24r3-p3x6-cqvx)
- GitHub Advisory Database: Mattermost [GHSA-jqgv-39mg-7c2r](https://github.com/advisories/GHSA-jqgv-39mg-7c2r) (MMSA-2026-00654), [GHSA-2g8v-grq3-hq2g](https://github.com/advisories/GHSA-2g8v-grq3-hq2g) (MMSA-2026-00644), [GHSA-mxq2-5jpg-7474](https://github.com/advisories/GHSA-mxq2-5jpg-7474) (MMSA-2026-00650), [GHSA-g5vr-6pgg-74qv](https://github.com/advisories/GHSA-g5vr-6pgg-74qv) (MMSA-2026-00667), [GHSA-h998-hxxj-8q83](https://github.com/advisories/GHSA-h998-hxxj-8q83) (MMSA-2026-00664)
- GitHub Advisory Database: Apache NiFi [GHSA-chxj-gxww-q98w](https://github.com/advisories/GHSA-chxj-gxww-q98w), [GHSA-8vm2-c32j-mvfr](https://github.com/advisories/GHSA-8vm2-c32j-mvfr), [GHSA-r2g5-993q-664g](https://github.com/advisories/GHSA-r2g5-993q-664g), [GHSA-qvj8-gwpm-4x49](https://github.com/advisories/GHSA-qvj8-gwpm-4x49)
- GitHub Advisory Database: October CMS [GHSA-xv9m-fm3w-8w5x / CVE-2026-46696](https://github.com/advisories/GHSA-xv9m-fm3w-8w5x)
- Related wiki pages: [Sept 16 identity-provider authority boundaries](2026-09-16-zitadel-keycloak-nezha-identity-provider-authority-boundaries-ghsa.md), [Sept 15 AI/agent local-surface week](2026-09-15-mcp-dns-rebinding-alternate-auth-path-and-sandbox-boundaries-ghsa.md)
