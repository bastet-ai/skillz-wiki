# Developer dashboard, identity handoff, and file-serving boundary checks

Source: hourly offensive-security scan, 2026-07-02, with July 3 and July 5 follow-ups. Primary entries: GitHub Advisory Database [GHSA-rh62-j648-g5qc](https://github.com/advisories/GHSA-rh62-j648-g5qc), [GHSA-g6g7-pvmx-m74p](https://github.com/advisories/GHSA-g6g7-pvmx-m74p), [GHSA-jphh-m39h-6gwx](https://github.com/advisories/GHSA-jphh-m39h-6gwx), [GHSA-6g2f-w7g3-77vf](https://github.com/advisories/GHSA-6g2f-w7g3-77vf), [GHSA-q8r6-xj3f-wrrm](https://github.com/advisories/GHSA-q8r6-xj3f-wrrm), [GHSA-6929-8p9f-26jx](https://github.com/advisories/GHSA-6929-8p9f-26jx), [GHSA-794g-x443-36f7](https://github.com/advisories/GHSA-794g-x443-36f7), [GHSA-5g75-477j-2c2f](https://github.com/advisories/GHSA-5g75-477j-2c2f), [GHSA-mm6c-5j6x-hq8m](https://github.com/advisories/GHSA-mm6c-5j6x-hq8m), [GHSA-fggg-964j-3j7h](https://github.com/advisories/GHSA-fggg-964j-3j7h), [GHSA-3ggm-c5m7-hfv5](https://github.com/advisories/GHSA-3ggm-c5m7-hfv5), [GHSA-82m5-3pcp-hccq](https://github.com/advisories/GHSA-82m5-3pcp-hccq), [GHSA-qhqw-rrw9-25rm](https://github.com/advisories/GHSA-qhqw-rrw9-25rm) / CVE-2025-65896, [GHSA-rxw2-pc8j-vxwm](https://github.com/advisories/GHSA-rxw2-pc8j-vxwm), [GHSA-58f6-6rj2-3v8r](https://github.com/advisories/GHSA-58f6-6rj2-3v8r), [GHSA-227r-jm2g-7cp4](https://github.com/advisories/GHSA-227r-jm2g-7cp4), [GHSA-q62h-354g-5r85](https://github.com/advisories/GHSA-q62h-354g-5r85), [GHSA-7fqc-p256-7pwj](https://github.com/advisories/GHSA-7fqc-p256-7pwj), and [GHSA-c96p-56gh-3pvw](https://github.com/advisories/GHSA-c96p-56gh-3pvw) / CVE-2026-14781.

These advisories are durable for operators because they repeat the same validation seams across developer tools, identity middleware, and file-serving helpers: unauthenticated dashboard APIs reaching SQL or shell primitives, trusted identity responses accepted outside their original issuer/request binding, static or media helpers reading/writing outside intended roots, and URL/upload/vector metadata helpers crossing into server-side fetch or query construction. Keep proofs to owned labs, disposable projects, synthetic identities, marker files, canary callbacks, and fixed-version negative controls.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-rh62-j648-g5qc](https://github.com/advisories/GHSA-rh62-j648-g5qc) | Recce `<= 1.49.0` | exposed Recce server query API can execute DuckDB-backed SQL that reaches filesystem read/write primitives | dbt/analytics review should treat local dashboard SQL consoles as filesystem boundaries, not just data-query surfaces. |
| [GHSA-g6g7-pvmx-m74p](https://github.com/advisories/GHSA-g6g7-pvmx-m74p), [GHSA-jphh-m39h-6gwx](https://github.com/advisories/GHSA-jphh-m39h-6gwx), [GHSA-6g2f-w7g3-77vf](https://github.com/advisories/GHSA-6g2f-w7g3-77vf) | 9router dashboard / MCP routes | unguarded tunnel install route, hardcoded fallback JWT secret, and header-based local-only gate can expose dashboard, tunnel, or MCP process authority | Agent/router assessments need route-coverage, default-secret, and locality-source checks before trusting dashboard controls. |
| [GHSA-q8r6-xj3f-wrrm](https://github.com/advisories/GHSA-q8r6-xj3f-wrrm), [GHSA-6929-8p9f-26jx](https://github.com/advisories/GHSA-6929-8p9f-26jx) | SimpleSAMLphp SP | responses or artifacts from one trusted IdP can satisfy state or TLS validation intended for another IdP under specific multi-IdP flows | SAML validation should bind issuer, request ID, artifact resolution, TLS trust, and downstream identity namespace in one decision table. |
| [GHSA-794g-x443-36f7](https://github.com/advisories/GHSA-794g-x443-36f7) | Keycloak encrypted SAML assertions | encrypted-assertion handling can drift from the expected authorization/validation path | Identity reviews should include encrypted and plaintext assertion variants for the same tenant/user controls. |
| [GHSA-c96p-56gh-3pvw](https://github.com/advisories/GHSA-c96p-56gh-3pvw) / CVE-2026-14781 | Keycloak OIDC broker with `trustEmail=true` and userinfo enabled | `email_verified=true` from the ID token can be applied to a different email address returned by userinfo | OIDC broker assessments should bind verification claims to the exact email/source response before account-linking or verified-email decisions. |
| [GHSA-5g75-477j-2c2f](https://github.com/advisories/GHSA-5g75-477j-2c2f) | GravitLauncher LaunchServer `FileServerHandler` | unauthenticated file server path handling can read process-accessible files, including signing keys and config secrets | Static download services need canonical request-target tests that stop at synthetic canaries and never touch real keys. |
| [GHSA-mm6c-5j6x-hq8m](https://github.com/advisories/GHSA-mm6c-5j6x-hq8m) | Algernon on Windows/NTFS | NTFS-equivalent names such as alternate data-stream or trailing-dot/space forms can bypass script-extension dispatch and return raw source | Windows path testing should include filesystem-equivalent names, not only `../` traversal. |
| [GHSA-fggg-964j-3j7h](https://github.com/advisories/GHSA-fggg-964j-3j7h), [GHSA-3ggm-c5m7-hfv5](https://github.com/advisories/GHSA-3ggm-c5m7-hfv5) | Spatie Laravel Media Library `< 11.23.0` | application-controlled media helpers can fetch arbitrary URLs or preserve dangerous double-extension/upload names depending on integration | Laravel media assessments should test helper-call reachability, redirect/callback behavior, and stored filename policy with benign uploads only. |
| [GHSA-82m5-3pcp-hccq](https://github.com/advisories/GHSA-82m5-3pcp-hccq) | agno ClickHouse vector backend | metadata keys/values passed to vector-store deletion can cross into SQL construction | AI/vector workflow reviews should fuzz metadata-to-query boundaries with seeded synthetic rows. |
| [GHSA-qhqw-rrw9-25rm](https://github.com/advisories/GHSA-qhqw-rrw9-25rm) / CVE-2025-65896 | asyncmy `<= 0.2.11` | crafted Python `dict` keys can cross from caller-controlled mapping shape into raw SQL text | Database-client reviews should test identifier/key material separately from parameter values, using query-log canaries only. |
| [GHSA-rxw2-pc8j-vxwm](https://github.com/advisories/GHSA-rxw2-pc8j-vxwm) | `fast-mcp-telegram` HTTP bearer sessions | bearer token strings are joined into session-file paths; exact reserved-name checks miss traversal aliases | MCP transport reviews should test whether token/user/session selectors can escape into filesystem-backed account selection. |
| [GHSA-58f6-6rj2-3v8r](https://github.com/advisories/GHSA-58f6-6rj2-3v8r), [GHSA-227r-jm2g-7cp4](https://github.com/advisories/GHSA-227r-jm2g-7cp4), [GHSA-q62h-354g-5r85](https://github.com/advisories/GHSA-q62h-354g-5r85), [GHSA-7fqc-p256-7pwj](https://github.com/advisories/GHSA-7fqc-p256-7pwj) | Steeltoe actuators and token-key resolver | `Host` controls management-port isolation, low-trust CF roles reach sensitive actuators, connection-string keys evade sanitizer, and JWKS cache keys lack issuer namespace/expiry | Control-plane reviews should pair listener-vs-header reachability, role matrices, fake env canaries, and multi-issuer `kid` collision checks. |

## Operator triage

1. **Start from exposure and role.** Confirm whether the dashboard, file server, media helper, SAML SP, or vector API is reachable by the tested principal. Do not assume a library advisory is exploitable unless the application exposes the vulnerable helper or route.
2. **Capture the crossed boundary, not secret contents.** Positive proof should be a marker file, fake JWT/session, synthetic IdP user, callback log, route decision table, or seeded database row. Never read production keys, configs, customer files, IdP metadata, media libraries, or model/vector data.
3. **Use paired negative controls.** For every positive canary, include a fixed version, patched route, non-vulnerable adapter, wrong role, wrong IdP, or canonicalized path that blocks the same action.
4. **Separate route bugs from deployment bugs.** 9router and Recce are most relevant when reachable from untrusted networks or exposed through tunnels/reverse proxies; prove the actual deployment topology before reporting impact.
5. **Normalize before policy.** For SAML, URLs, request targets, filenames, vector metadata, and Host/Origin/locality checks, record both raw input and canonical values used by the security decision.

## Replayable validation boundaries

### Recce DuckDB query-to-filesystem check

- Preconditions: disposable Recce project, affected `recce` version, DuckDB-backed configuration, exposed server route under test, and a scratch directory containing only marker files.
- Establish that unauthenticated or lower-trust access can reach the query-run API.
- Execute only harmless DuckDB filesystem canaries against a temp path you control, such as reading a synthetic marker file or writing a marker into a disposable scratch directory.
- Positive evidence: the server process reads or writes the marker path through the query route.
- Negative controls: Recce `>= 1.50.0`, authentication in front of the server, non-DuckDB adapter behavior, and a non-writable/read-only application filesystem.
- Do not read `.env`, dbt profiles, SSH keys, cloud credentials, notebooks, model artifacts, or application source outside the canary directory.

### 9router dashboard/MCP authority checks

- Preconditions: disposable 9router lab, affected versions, fake JWT secret state, fake machine ID/CLI-token material, inert MCP tools, and no live operator credentials.
- Route coverage: enumerate dashboard and API route families and compare which routes pass through the same guard. Positive evidence is a spawn/tunnel/MCP-capable route reachable without the documented guard while the guarded route rejects the same request.
- Default secret: with `JWT_SECRET` intentionally unset in the lab, mint only a disposable dashboard token for a fake user and verify whether the dashboard accepts it. Negative control is a non-default secret or fixed version.
- Local-only gate: behind a controlled proxy/tunnel, vary `Host` and `Origin` while recording the TCP peer address and final access decision. Positive evidence is loopback-only behavior granted from a non-loopback peer because headers claimed locality.
- MCP/process evidence should be inert: a marker-only tool invocation or dry-run argv log. Do not install tailscale, pass real sudo passwords, run shell payloads, or operate on production agent profiles.

### July 6 9router provider, usage, database, and rate-limit follow-up

Later July 6 entries add three adjacent 9router checks: [GHSA-vjc7-jrh9-9j86](https://github.com/advisories/GHSA-vjc7-jrh9-9j86) for unauthenticated provider CRUD and API-key leakage through usage stats, [GHSA-qvfm-67h2-2qfx](https://github.com/advisories/GHSA-qvfm-67h2-2qfx) / CVE-2026-55500 for sensitive information exposure and unprotected database import/export, and [GHSA-7cfm-pqrj-xgq7](https://github.com/advisories/GHSA-7cfm-pqrj-xgq7) / CVE-2026-55501 for login brute-force protection bypass via spoofed `X-Forwarded-For`.

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-vjc7-jrh9-9j86](https://github.com/advisories/GHSA-vjc7-jrh9-9j86) | unauthenticated provider routes and usage stats can expose or mutate model/provider configuration and API-key material | Agent-router reviews should enumerate provider, usage, stats, and model-management routes separately from the main dashboard guard. |
| [GHSA-qvfm-67h2-2qfx](https://github.com/advisories/GHSA-qvfm-67h2-2qfx) | database import/export endpoints can expose credential-bearing state or accept attacker-controlled state | Backup/import helpers are control-plane boundaries; prove only with fake provider keys and disposable database snapshots. |
| [GHSA-7cfm-pqrj-xgq7](https://github.com/advisories/GHSA-7cfm-pqrj-xgq7) | brute-force rate limiting trusts caller-supplied forwarding headers | Rate-limit validation should record trusted-proxy topology and peer IP vs forwarded-IP decisions before claiming bypass. |

- Preconditions: disposable 9router lab, fake provider credentials, synthetic usage rows, disposable database exports, and a controlled proxy/tunnel when testing forwarding headers.
- For provider and usage routes, use fake API keys with obvious marker prefixes and verify only route access, redaction state, and CRUD effects on disposable provider entries.
- For database import/export, export a lab database containing only marker users/providers; import only a marker snapshot into the same disposable lab. Do not collect real SQLite files, tokens, prompts, usage history, or provider secrets.
- For rate limiting, vary `X-Forwarded-For` behind known proxy and direct-connect paths while recording TCP peer, configured trusted proxy state, and throttle decisions. Do not conduct password spraying against real accounts.
- Negative controls: patched versions, route-level auth on every provider/stats/import/export endpoint, secret redaction at response boundaries, import role checks, and rate-limit keys derived from trusted proxy metadata rather than arbitrary browser headers.

### SAML issuer, request, artifact, and encryption binding checks

- Preconditions: lab SimpleSAMLphp or Keycloak deployment, at least two lab IdPs with different trust labels, disposable SP/client, synthetic users, and lab signing/encryption keys.
- Build a matrix for: expected IdP A vs response from IdP B, signed assertion with and without `SubjectConfirmationData/InResponseTo`, unsigned outer response `InResponseTo`, artifact resolution over each configured TLS trust path, plaintext assertion, and encrypted assertion.
- Positive evidence: the SP/client issues a lab session or token for an assertion/artifact that does not match the expected issuer, request ID, artifact TLS trust anchor, audience, tenant, or encrypted-assertion authorization path.
- Negative controls: patched SimpleSAMLphp, fixed Keycloak behavior, single-IdP deployment, explicit issuer pinning, and assertions with wrong signatures rejected before session creation.
- Stop at lab session issuance and redacted decision tables; never access real applications, customer tenants, real SSO sessions, or live IdP metadata.

### Keycloak OIDC `email_verified` source-binding check

- Preconditions: lab Keycloak realm, disposable client, attacker-controlled or mock upstream OIDC provider, `trustEmail=true`, userinfo endpoint enabled, synthetic users only, and no production account linking.
- Configure the upstream provider so the ID token returns `email_verified=true` for one controlled address while the userinfo response returns a different controlled address.
- Positive evidence: Keycloak stores or issues tokens for the userinfo email as verified even though the verification claim came from an ID token bound to another email value.
- Negative controls: fixed Keycloak behavior, `trustEmail=false`, userinfo disabled, matching email values only, or explicit application-side verification before account linking.
- Stop at realm/user metadata and redacted token claims. Do not target real IdPs, real inboxes, customer accounts, production tenants, or live account-takeover flows.

### File-server and Windows filename canonicalization checks

- Preconditions: disposable LaunchServer or Algernon lab, synthetic web root, marker files only, and a process account with no access to sensitive host paths.
- LaunchServer: request only known canary filenames under and outside the intended file base. Include raw request-target variants that omit a leading slash if that is the parser differential under review.
- Algernon on Windows: create a harmless script with no secrets and request NTFS-equivalent names such as trailing-dot, trailing-space, or alternate data-stream forms. Positive evidence is raw source for the harmless script where normal requests execute/render it.
- Negative controls: patched version, canonical realpath containment after URL parsing, extension dispatch based on the resolved filesystem object, and requests for non-canary files blocked.
- Do not request `.keys`, config files, database credentials, production scripts, or private user uploads.

### Media helper, URL fetch, upload-name, and vector metadata checks

- Preconditions: local Laravel app using Spatie Media Library, local agno/ClickHouse vector harness, asyncmy harness connected only to a disposable database, owned callback endpoint, synthetic uploads, seeded marker rows, and no production data.
- Media URL fetch: exercise only application paths that call `addMediaFromUrl()` with an owned callback URL and controlled redirects. Positive evidence is a server-originated callback from the application.
- Upload sanitizer: upload benign marker files with double-extension or omitted-extension variants and record stored filename, content type, web serving behavior, and fixed-version rejection. Do not upload executable payloads.
- Vector metadata: seed a single synthetic row and send metadata keys/values designed to change only the test query shape. Positive evidence can be a harmless SQL error mentioning a marker token or an unintended mutation of only the synthetic row.
- asyncmy mapping keys: instrument query logging against a scratch schema, then pass mapping/dict keys containing inert SQL marker tokens through only the affected helper path. Positive evidence is the key material changing the generated SQL text or query structure before execution.
- Negative controls: Spatie `>= 11.23.0`, application-level URL allowlists, forced attachment/non-executable storage, parameterized vector queries, metadata key allowlists, and database-client code that treats keys as fixed application identifiers rather than request-controlled input.

## July 3 fast-mcp Telegram and Steeltoe actuator follow-up

The July 3 updated feed added two adjacent operator patterns that belong with this dashboard/control-plane batch rather than a standalone page.

### MCP bearer-token-to-session-file boundary

- Preconditions: isolated `fast-mcp-telegram` HTTP server, disposable Telegram test account or mocked session files, temp config directory, and account-prefixed tools configured with inert sinks.
- Create a canary session file representing the reserved/default account, then try bearer-token variants that include path separators or dot segments.
- Positive evidence: the token selects the reserved/default session despite exact reserved-name rejection. Capture only session selector, account label, and inert tool availability.
- Negative controls: tokens rejected if they contain path separators, normalized session path constrained to the session directory, reserved names rejected after canonicalization, and patched behavior.
- Do not read real messages, send real messages, or capture MTProto session files from operator machines.

### Steeltoe actuator and JWKS control-plane boundary

- Preconditions: Steeltoe app with synthetic actuator values, two lab JWT issuers with controlled `kid`s, fake connection strings, and no real heap dumps or database credentials.
- Compare public listener requests whose `Host` header names the management port against requests that reach the actual management listener. Positive evidence is actuator access that follows spoofed `Host` rather than the bound socket/port.
- Build a Cloud Foundry role-to-endpoint matrix with low-trust lab roles. Positive evidence is access to sensitive actuator families such as heap dump, thread dump, or environment where the expected sensitive-data permission is absent. Record route/status only, not dump contents.
- Seed `/actuator/env` or `/cloudfoundryapplication/env` with fake `ConnectionStrings:*` and Steeltoe connector keys. Positive evidence is an unsanitized canary value containing only fake credentials.
- For JWT validation, configure two issuers with the same `kid` and different keys. Positive evidence is a token/key decision that uses a key cached for the wrong issuer or keeps a revoked key trusted until process restart.
- Do not dump heap/thread data, real environment variables, production tokens, customer rows, service bindings, or backing database contents.

## Reporting notes

Lead with the crossed boundary:

- **Unauthenticated Recce query route -> DuckDB filesystem primitive**
- **9router public/tunnel route or default secret -> dashboard/MCP process authority**
- **SAML response/artifact/encrypted assertion -> wrong issuer/request/client session**
- **OIDC ID-token verification claim -> different userinfo email trusted as verified**
- **File-server request target or NTFS-equivalent name -> outside-root read or raw script source**
- **Media URL/upload metadata, vector metadata, or DB mapping keys -> server fetch, stored filename bypass, SQL construction, or generated-SQL mutation**
- **Bearer token string -> filesystem-backed MCP session selection**
- **Host header / CF role / shared `kid` -> actuator or token-authority drift**

Strong reports include affected version, deployment topology, raw and normalized input, exact route/helper, test role, synthetic canary evidence, and fixed-version or configuration negative controls.

## Reviewed but not promoted here

- [GHSA-q675-qj96-32m9](https://github.com/advisories/GHSA-q675-qj96-32m9), [GHSA-5pmv-rx8r-wmv5](https://github.com/advisories/GHSA-5pmv-rx8r-wmv5), [GHSA-66m8-c62j-h6v5](https://github.com/advisories/GHSA-66m8-c62j-h6v5), [GHSA-2v8p-fqpx-2q3w](https://github.com/advisories/GHSA-2v8p-fqpx-2q3w), and nearby Zebra/JXL resource-exhaustion or crash advisories were skipped as standalone wiki items because they did not add a non-availability operator workflow in this scan.
- [GHSA-v8rp-6xcv-fwgh](https://github.com/advisories/GHSA-v8rp-6xcv-fwgh) was not promoted because the advisory describes Kiwi TCMS `/init-db/` repeat access as a reentrant/no-op migration status path.
- [GHSA-5j8p-5rrj-8wjg](https://github.com/advisories/GHSA-5j8p-5rrj-8wjg) was noted as a generic music-directory prefix traversal; it did not add a distinct workflow beyond the file-server path-boundary checks above.
- [GHSA-rcjc-c4pj-xxrp](https://github.com/advisories/GHSA-rcjc-c4pj-xxrp), [GHSA-6r7r-jj8h-pq6v](https://github.com/advisories/GHSA-6r7r-jj8h-pq6v), and [GHSA-5843-p793-ghmm](https://github.com/advisories/GHSA-5843-p793-ghmm) were processed without a new page because the July 2 update did not add a reusable operator workflow beyond existing LDAP input, unsafe deserialization, or availability-only multipart checks.
