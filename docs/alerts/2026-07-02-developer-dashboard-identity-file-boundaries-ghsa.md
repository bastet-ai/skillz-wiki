# Developer dashboard, identity handoff, and file-serving boundary checks

Source: hourly offensive-security scan, 2026-07-02. Primary entries: GitHub Advisory Database [GHSA-rh62-j648-g5qc](https://github.com/advisories/GHSA-rh62-j648-g5qc), [GHSA-g6g7-pvmx-m74p](https://github.com/advisories/GHSA-g6g7-pvmx-m74p), [GHSA-jphh-m39h-6gwx](https://github.com/advisories/GHSA-jphh-m39h-6gwx), [GHSA-6g2f-w7g3-77vf](https://github.com/advisories/GHSA-6g2f-w7g3-77vf), [GHSA-q8r6-xj3f-wrrm](https://github.com/advisories/GHSA-q8r6-xj3f-wrrm), [GHSA-6929-8p9f-26jx](https://github.com/advisories/GHSA-6929-8p9f-26jx), [GHSA-794g-x443-36f7](https://github.com/advisories/GHSA-794g-x443-36f7), [GHSA-5g75-477j-2c2f](https://github.com/advisories/GHSA-5g75-477j-2c2f), [GHSA-mm6c-5j6x-hq8m](https://github.com/advisories/GHSA-mm6c-5j6x-hq8m), [GHSA-fggg-964j-3j7h](https://github.com/advisories/GHSA-fggg-964j-3j7h), [GHSA-3ggm-c5m7-hfv5](https://github.com/advisories/GHSA-3ggm-c5m7-hfv5), and [GHSA-82m5-3pcp-hccq](https://github.com/advisories/GHSA-82m5-3pcp-hccq).

These advisories are durable for operators because they repeat the same validation seams across developer tools, identity middleware, and file-serving helpers: unauthenticated dashboard APIs reaching SQL or shell primitives, trusted identity responses accepted outside their original issuer/request binding, static or media helpers reading/writing outside intended roots, and URL/upload/vector metadata helpers crossing into server-side fetch or query construction. Keep proofs to owned labs, disposable projects, synthetic identities, marker files, canary callbacks, and fixed-version negative controls.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-rh62-j648-g5qc](https://github.com/advisories/GHSA-rh62-j648-g5qc) | Recce `<= 1.49.0` | exposed Recce server query API can execute DuckDB-backed SQL that reaches filesystem read/write primitives | dbt/analytics review should treat local dashboard SQL consoles as filesystem boundaries, not just data-query surfaces. |
| [GHSA-g6g7-pvmx-m74p](https://github.com/advisories/GHSA-g6g7-pvmx-m74p), [GHSA-jphh-m39h-6gwx](https://github.com/advisories/GHSA-jphh-m39h-6gwx), [GHSA-6g2f-w7g3-77vf](https://github.com/advisories/GHSA-6g2f-w7g3-77vf) | 9router dashboard / MCP routes | unguarded tunnel install route, hardcoded fallback JWT secret, and header-based local-only gate can expose dashboard, tunnel, or MCP process authority | Agent/router assessments need route-coverage, default-secret, and locality-source checks before trusting dashboard controls. |
| [GHSA-q8r6-xj3f-wrrm](https://github.com/advisories/GHSA-q8r6-xj3f-wrrm), [GHSA-6929-8p9f-26jx](https://github.com/advisories/GHSA-6929-8p9f-26jx) | SimpleSAMLphp SP | responses or artifacts from one trusted IdP can satisfy state or TLS validation intended for another IdP under specific multi-IdP flows | SAML validation should bind issuer, request ID, artifact resolution, TLS trust, and downstream identity namespace in one decision table. |
| [GHSA-794g-x443-36f7](https://github.com/advisories/GHSA-794g-x443-36f7) | Keycloak encrypted SAML assertions | encrypted-assertion handling can drift from the expected authorization/validation path | Identity reviews should include encrypted and plaintext assertion variants for the same tenant/user controls. |
| [GHSA-5g75-477j-2c2f](https://github.com/advisories/GHSA-5g75-477j-2c2f) | GravitLauncher LaunchServer `FileServerHandler` | unauthenticated file server path handling can read process-accessible files, including signing keys and config secrets | Static download services need canonical request-target tests that stop at synthetic canaries and never touch real keys. |
| [GHSA-mm6c-5j6x-hq8m](https://github.com/advisories/GHSA-mm6c-5j6x-hq8m) | Algernon on Windows/NTFS | NTFS-equivalent names such as alternate data-stream or trailing-dot/space forms can bypass script-extension dispatch and return raw source | Windows path testing should include filesystem-equivalent names, not only `../` traversal. |
| [GHSA-fggg-964j-3j7h](https://github.com/advisories/GHSA-fggg-964j-3j7h), [GHSA-3ggm-c5m7-hfv5](https://github.com/advisories/GHSA-3ggm-c5m7-hfv5) | Spatie Laravel Media Library `< 11.23.0` | application-controlled media helpers can fetch arbitrary URLs or preserve dangerous double-extension/upload names depending on integration | Laravel media assessments should test helper-call reachability, redirect/callback behavior, and stored filename policy with benign uploads only. |
| [GHSA-82m5-3pcp-hccq](https://github.com/advisories/GHSA-82m5-3pcp-hccq) | agno ClickHouse vector backend | metadata keys/values passed to vector-store deletion can cross into SQL construction | AI/vector workflow reviews should fuzz metadata-to-query boundaries with seeded synthetic rows. |

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

### SAML issuer, request, artifact, and encryption binding checks

- Preconditions: lab SimpleSAMLphp or Keycloak deployment, at least two lab IdPs with different trust labels, disposable SP/client, synthetic users, and lab signing/encryption keys.
- Build a matrix for: expected IdP A vs response from IdP B, signed assertion with and without `SubjectConfirmationData/InResponseTo`, unsigned outer response `InResponseTo`, artifact resolution over each configured TLS trust path, plaintext assertion, and encrypted assertion.
- Positive evidence: the SP/client issues a lab session or token for an assertion/artifact that does not match the expected issuer, request ID, artifact TLS trust anchor, audience, tenant, or encrypted-assertion authorization path.
- Negative controls: patched SimpleSAMLphp, fixed Keycloak behavior, single-IdP deployment, explicit issuer pinning, and assertions with wrong signatures rejected before session creation.
- Stop at lab session issuance and redacted decision tables; never access real applications, customer tenants, real SSO sessions, or live IdP metadata.

### File-server and Windows filename canonicalization checks

- Preconditions: disposable LaunchServer or Algernon lab, synthetic web root, marker files only, and a process account with no access to sensitive host paths.
- LaunchServer: request only known canary filenames under and outside the intended file base. Include raw request-target variants that omit a leading slash if that is the parser differential under review.
- Algernon on Windows: create a harmless script with no secrets and request NTFS-equivalent names such as trailing-dot, trailing-space, or alternate data-stream forms. Positive evidence is raw source for the harmless script where normal requests execute/render it.
- Negative controls: patched version, canonical realpath containment after URL parsing, extension dispatch based on the resolved filesystem object, and requests for non-canary files blocked.
- Do not request `.keys`, config files, database credentials, production scripts, or private user uploads.

### Media helper, URL fetch, upload-name, and vector metadata checks

- Preconditions: local Laravel app using Spatie Media Library, local agno/ClickHouse vector harness, owned callback endpoint, synthetic uploads, seeded marker rows, and no production data.
- Media URL fetch: exercise only application paths that call `addMediaFromUrl()` with an owned callback URL and controlled redirects. Positive evidence is a server-originated callback from the application.
- Upload sanitizer: upload benign marker files with double-extension or omitted-extension variants and record stored filename, content type, web serving behavior, and fixed-version rejection. Do not upload executable payloads.
- Vector metadata: seed a single synthetic row and send metadata keys/values designed to change only the test query shape. Positive evidence can be a harmless SQL error mentioning a marker token or an unintended mutation of only the synthetic row.
- Negative controls: Spatie `>= 11.23.0`, application-level URL allowlists, forced attachment/non-executable storage, parameterized vector queries, and metadata key allowlists.

## Reporting notes

Lead with the crossed boundary:

- **Unauthenticated Recce query route -> DuckDB filesystem primitive**
- **9router public/tunnel route or default secret -> dashboard/MCP process authority**
- **SAML response/artifact/encrypted assertion -> wrong issuer/request/client session**
- **File-server request target or NTFS-equivalent name -> outside-root read or raw script source**
- **Media URL/upload metadata or vector metadata -> server fetch, stored filename bypass, or SQL construction**

Strong reports include affected version, deployment topology, raw and normalized input, exact route/helper, test role, synthetic canary evidence, and fixed-version or configuration negative controls.

## Reviewed but not promoted here

- [GHSA-q675-qj96-32m9](https://github.com/advisories/GHSA-q675-qj96-32m9), [GHSA-5pmv-rx8r-wmv5](https://github.com/advisories/GHSA-5pmv-rx8r-wmv5), [GHSA-66m8-c62j-h6v5](https://github.com/advisories/GHSA-66m8-c62j-h6v5), [GHSA-2v8p-fqpx-2q3w](https://github.com/advisories/GHSA-2v8p-fqpx-2q3w), and nearby Zebra/JXL resource-exhaustion or crash advisories were skipped as standalone wiki items because they did not add a non-availability operator workflow in this scan.
- [GHSA-v8rp-6xcv-fwgh](https://github.com/advisories/GHSA-v8rp-6xcv-fwgh) was not promoted because the advisory describes Kiwi TCMS `/init-db/` repeat access as a reentrant/no-op migration status path.
- [GHSA-5j8p-5rrj-8wjg](https://github.com/advisories/GHSA-5j8p-5rrj-8wjg) was noted as a generic music-directory prefix traversal; it did not add a distinct workflow beyond the file-server path-boundary checks above.
