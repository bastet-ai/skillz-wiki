# Web app data, render, and method-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh web-application batch updated on **2026-05-06** where tenant visibility, identifier handling, rendering, request methods, and data access crossed trust boundaries.

## Advisories covered

- **Lemmy private-instance metadata exposure** — [GHSA-jmxc-hhwx-gvv3](https://github.com/advisories/GHSA-jmxc-hhwx-gvv3): private instances exposed multi-community metadata without authentication.
- **Kyverno policy-reporter-ui stored XSS** — [GHSA-q98m-7w8c-w388](https://github.com/advisories/GHSA-q98m-7w8c-w388): stored property values rendered through `PropertyCard` could execute script.
- **Daptin fuzzy-search SQL injection** — [GHSA-pwqg-q8pg-pp6r](https://github.com/advisories/GHSA-pwqg-q8pg-pp6r): unvalidated column names reached raw SQL.
- **CyberChef XSS** — [GHSA-h4hv-92pp-pcjg](https://github.com/advisories/GHSA-h4hv-92pp-pcjg): crafted input could cross into script execution.
- **Bagisto SSRF and XSS** — [GHSA-x3f9-vcp2-hgcw](https://github.com/advisories/GHSA-x3f9-vcp2-hgcw), [GHSA-65fp-7g2v-658r](https://github.com/advisories/GHSA-65fp-7g2v-658r): server-side fetch and render paths need explicit origin and HTML boundaries.
- **Hatchet cross-tenant task disclosure** — [GHSA-55gc-6fmc-fpx9](https://github.com/advisories/GHSA-55gc-6fmc-fpx9): `listTasksByDAGIds` could disclose tasks across tenants.
- **xxl-job resource injection, authorization, and weak token generation** — [GHSA-gw2x-mfwr-h46p](https://github.com/advisories/GHSA-gw2x-mfwr-h46p), [GHSA-565h-44m8-4c2v](https://github.com/advisories/GHSA-565h-44m8-4c2v), [GHSA-gjx6-h8hm-c9rq](https://github.com/advisories/GHSA-gjx6-h8hm-c9rq), [GHSA-6rq7-m52p-8pqg](https://github.com/advisories/GHSA-6rq7-m52p-8pqg): scheduler resource identifiers and handler IDs need ownership/authorization checks before runtime effects, and admin/session token material must use modern high-entropy generation rather than low-effort password hashing.
- **Flight framework batch** — [GHSA-qrch-52m5-vv85](https://github.com/advisories/GHSA-qrch-52m5-vv85), [GHSA-vxrr-w42w-w76g](https://github.com/advisories/GHSA-vxrr-w42w-w76g), [GHSA-xwqr-rcqg-22mr](https://github.com/advisories/GHSA-xwqr-rcqg-22mr), [GHSA-3xjv-pmf2-gf2q](https://github.com/advisories/GHSA-3xjv-pmf2-gf2q), [GHSA-fcx8-ph5r-mxr4](https://github.com/advisories/GHSA-fcx8-ph5r-mxr4): default error disclosure, method override, identifier SQL injection, CLI path traversal, and JSONP callback XSS.

## Why this is durable

The recurring pattern is that framework convenience crossed from labels, callbacks, route methods, or tenant IDs into authority. Treat every identifier, rendering callback, method override, and server-side fetch target as policy input, not as trusted application metadata.

## Immediate triage

1. Patch the affected applications and frameworks as vendor fixes land; prioritize exposed admin, scheduler/control-plane, multi-tenant, and public render surfaces. For `xxl-job-admin`, target **3.2.0+** for the token-generation fix.
2. Disable JSONP, method override, and developer error disclosure unless a route has an explicit business need and tests.
3. Add tenant-scoped authorization checks around list/query helpers, not only around route entrypoints.
4. Replace dynamic SQL identifiers with allowlisted schema maps; parameterization does not protect table/column names. For scheduler/admin tools such as xxl-job, verify handler/remove operations are scoped to the caller's tenant/project and cannot address arbitrary resource IDs. Rotate or invalidate weakly generated admin tokens/secrets after patching.
5. Gate server-side fetch features with canonicalized DNS/IP checks, redirect revalidation, and egress allowlists.

## Durable controls

- Encode output by context and keep stored user properties as data through the final render step.
- Bind every query helper to tenant, project, and resource ownership before applying caller-supplied IDs.
- Treat method-override, callback, scheduler, handler-removal, and token-generation features as privileged framework extensions with deny-by-default configuration, object-level authorization, audit logging, and cryptographically strong random secrets.
- Exercise CLI generators and developer tooling with traversal payloads, not only HTTP handlers.
