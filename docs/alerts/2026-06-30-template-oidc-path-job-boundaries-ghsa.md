# Template, OIDC discovery, path-prefix, and job-dashboard boundary checks

Source: hourly offensive-security scan, 2026-06-30. Primary entries: GitHub Advisory Database [GHSA-f5mr-q85p-6hh6](https://github.com/advisories/GHSA-f5mr-q85p-6hh6) / CVE-2026-49478, [GHSA-85jm-cwp2-mvpv](https://github.com/advisories/GHSA-85jm-cwp2-mvpv) / CVE-2026-48796, [GHSA-qcm7-3vpr-hj5h](https://github.com/advisories/GHSA-qcm7-3vpr-hj5h) / CVE-2026-48795, [GHSA-389x-rgxr-8m33](https://github.com/advisories/GHSA-389x-rgxr-8m33) / CVE-2026-48592, and [GHSA-x7qq-m748-8p2c](https://github.com/advisories/GHSA-x7qq-m748-8p2c) / CVE-2026-49820.

These advisories are durable for operators because they expose repeatable trust-boundary patterns: OIDC issuer discovery following redirects into SSRF or JWKS substitution, embedded-browser scheme handlers using raw prefix path containment, nested form bodies reaching prototype setters after an incomplete patch, read-only job-dashboard users modifying queued worker classes, and return/continue URL validators disagreeing with browser redirect parsing.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-f5mr-q85p-6hh6](https://github.com/advisories/GHSA-f5mr-q85p-6hh6) / CVE-2026-49478 | Sigstore Fulcio OIDC discovery client | issuer metadata fetch followed cross-host redirects, enabling blind SSRF, JWKS substitution, and Kubernetes service-account token leakage in affected deployments | Treat OIDC discovery, JWKS, CRL, OCSP, and federation metadata clients as server-side fetchers; prove only with owned issuer/callback hosts and fake tokens. |
| [GHSA-85jm-cwp2-mvpv](https://github.com/advisories/GHSA-85jm-cwp2-mvpv) / CVE-2026-48796 | CefSharp `FolderSchemeHandlerFactory` | decoded request paths were allowed when the final path string started with `rootFolder`, so prefix-sharing siblings such as `www2` could escape `www` | Embedded browser custom schemes need canonical directory-boundary tests, especially in desktop apps that expose local documents through app-origin URLs. |
| [GHSA-qcm7-3vpr-hj5h](https://github.com/advisories/GHSA-qcm7-3vpr-hj5h) / CVE-2026-48795 | `@adonisjs/bodyparser` | nested form keys such as `user.__proto__.polluted` bypassed a direct `__proto__` patch and polluted `Object.prototype` | Body parsers and multipart/form helpers need nested dangerous-key matrices, not just top-level `__proto__` tests. |
| [GHSA-389x-rgxr-8m33](https://github.com/advisories/GHSA-389x-rgxr-8m33) / CVE-2026-48592 | `oban_web` LiveView job detail | `save-job` lacked the authorization check used by neighboring job actions, letting read-only users overwrite a queued job's worker module | Admin dashboards should be tested for event-handler authorization drift: read-only UI state does not prove write handlers are gated. |
| [GHSA-x7qq-m748-8p2c](https://github.com/advisories/GHSA-x7qq-m748-8p2c) / CVE-2026-49820 | Probo `saferedirect` | path normalization plus backslash handling let a relative `continue` URL become an external browser redirect | Return-url testing should include dot segments, encoded separators, and backslash parser differentials across validator, framework redirect helper, and browser. |

Adjacent Open Babel parser memory-safety advisories, duplicate Open Babel advisories, Sigstore Timestamp Authority metric-cardinality OOM, and `oban_web` cron expression memory exhaustion were processed but not promoted as primary workflows here because they are parser/resource-exhaustion focused or availability-only without a stronger reusable operator boundary for this wiki update.

## Replayable validation boundaries

### Fulcio OIDC discovery redirect and JWKS substitution harness

- Preconditions: isolated Fulcio deployment or explicit customer-approved lab, an owned OIDC issuer domain, an owned redirect/callback collector, fake identities, and no production signing path.
- Configure a canary issuer whose `/.well-known/openid-configuration` responds with a cross-host redirect to an owned collector or to a second owned metadata host.
- Positive SSRF evidence is limited to callback method/path/source metadata and a canary issuer label. Do not redirect to cloud metadata, Kubernetes API servers, loopback admin ports, or internal production services.
- For JWKS substitution, use a fake issuer and fake signing key in the lab. Show whether discovery accepts metadata/JWKS from the redirected authority and whether a synthetic token signed by the substitute key is trusted.
- If Kubernetes service-account token behavior is in scope, prove only with a fake projected-token marker in a throwaway namespace. Never print, collect, or reuse real service-account tokens.
- Negative controls: no cross-host redirects during discovery, issuer/JWKS authority pinning, redirect target allowlists, and token issuer/audience checks bound to the configured issuer.

### CefSharp folder-scheme path containment harness

- Preconditions: desktop app lab or source-level harness using `FolderSchemeHandlerFactory`, a configured root directory, and synthetic sibling canary files.
- Create a root like `/tmp/skillz-app/www` and a sibling `/tmp/skillz-app/www2/skillz-cef-canary.txt`.
- Request the canary through the custom scheme using traversal or normalized paths that resolve to the sibling while preserving a raw string prefix with the root.
- Positive evidence is a path-resolution table: requested URL, decoded path, canonical final path, expected denial, and served canary body.
- Do not read user home directories, application secrets, browser profile data, or customer documents.
- Negative controls: `Path.GetFullPath` plus directory-separator boundary checks, symlink policy decisions, and tests for prefix-sharing siblings.

### AdonisJS nested prototype-pollution bodyparser harness

- Preconditions: disposable AdonisJS app or staging endpoint that parses form/multipart bodies and then reflects object-shape decisions into a harmless canary sink.
- Send baseline top-level dangerous keys such as `__proto__[skillz]=x` and nested variants such as `user.__proto__.skillz=x` or `user[constructor][prototype][skillz]=x`.
- Positive evidence is a fresh process where an inert property appears on `{}` or influences a canary-only branch after parsing, while a fixed version rejects or strips it.
- Keep the sink harmless: log a marker, render a synthetic field, or assert in a local unit test. Do not use polluted prototypes to alter authentication, authorization, template rendering, or command execution in production.
- Negative controls: recursive dangerous-key rejection at every path segment, null-prototype containers for nested objects, and cleanup between tests to avoid process-global contamination.

### `oban_web` job-handler authorization harness

- Preconditions: lab Phoenix/Oban application, `oban_web` affected version, one queued canary job, and two users: read-only dashboard user and write-capable operator.
- As the read-only user, confirm the UI does not expose save/edit controls for worker mutation, then send the LiveView `save-job` event directly with a harmless worker module that records only `skillz-oban-canary` when executed.
- Positive evidence is the queued job's worker field changing or the canary worker executing despite the read-only role.
- Do not point jobs at production worker modules, external integrations, payment/refund tasks, email senders, or destructive maintenance jobs.
- Negative controls: every LiveView event handler calls the same authorization helper as destructive sibling actions, job mutations are audited, and read-only roles cannot send state-changing events successfully.

### Probo return-url parser-differential harness

- Preconditions: owned Probo deployment or lab using affected `saferedirect`, a disposable login/magic-link flow, and an owned external canary domain.
- Test `continue` or equivalent return parameters with relative paths containing dot segments, encoded separators, and backslashes, such as `/../\\canary.example/path`, using only your owned canary domain.
- Capture three views of the same input: application validator decision, framework-generated `Location` header, and actual browser destination.
- Positive evidence is a value accepted as same-origin by the validator but interpreted by the browser as an external authority.
- Do not use phishing pages, real IdP flows, production trust-center links, or third-party domains as proof.
- Negative controls: URL normalization before validation, rejection of backslashes and encoded authority separators, and validation against the final `Location` value actually emitted.

## Reporting notes

- Lead with the precise mismatch: **configured issuer to redirected metadata/JWKS authority**, **custom scheme root to prefix-sharing sibling path**, **nested parser key to process-global prototype**, **read-only dashboard role to state-changing LiveView event**, or **return-url validator to browser redirect authority**.
- Include versions, preconditions, exact object path or URL shape, expected denial, observed canary-only result, and fixed-version negative control.
- Keep proof artifacts inert and scoped: fake issuers, owned callbacks, synthetic files, local prototype markers, disposable jobs, and owned redirect domains only.
