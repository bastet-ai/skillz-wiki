# Auth middleware, VM socket, and supply-chain verifier boundary checks

Source: hourly offensive-security scan, 2026-06-30. Primary entries: GitHub Advisory Database [GHSA-g4w6-vmgf-xqvx](https://github.com/advisories/GHSA-g4w6-vmgf-xqvx) / CVE-2026-49473, [GHSA-47p6-69vm-vw6v](https://github.com/advisories/GHSA-47p6-69vm-vw6v) / CVE-2026-9495, [GHSA-wpqm-4gwx-w843](https://github.com/advisories/GHSA-wpqm-4gwx-w843) / CVE-2026-44598, [GHSA-fcvm-3cpj-f9qx](https://github.com/advisories/GHSA-fcvm-3cpj-f9qx) / CVE-2026-43827, [GHSA-7jcp-v9w4-wjmg](https://github.com/advisories/GHSA-7jcp-v9w4-wjmg) / CVE-2026-7374, [GHSA-qqw8-7c2r-jxch](https://github.com/advisories/GHSA-qqw8-7c2r-jxch) / CVE-2026-48791, [GHSA-gq7g-vg2q-jvq3](https://github.com/advisories/GHSA-gq7g-vg2q-jvq3) / CVE-2026-42782, and [GHSA-vr35-jm2f-8wg2](https://github.com/advisories/GHSA-vr35-jm2f-8wg2) / CVE-2026-42797.

These advisories are durable because they expose reusable test patterns: authorization middleware parsing a different request target than the router, session/redirect state crossing into server-side fetches or fixed authenticated sessions, namespace-limited VM console access crossing into host Unix sockets, signed-artifact verification missing a certificate-time binding, and identity-platform extension points crossing sandbox or data-query boundaries. Keep validation to owned apps, disposable tenants, lab VMs, synthetic signatures, and canary identity records.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-g4w6-vmgf-xqvx](https://github.com/advisories/GHSA-g4w6-vmgf-xqvx) / CVE-2026-49473 | `@cedar-policy/authorization-for-expressjs` | Cedar action matching used `req.originalUrl` including the query string while Express routed by path only | Test auth middleware for request-target parser drift: `/users/?x=1` can authorize as a less-sensitive parameterized route while the app executes the collection handler. |
| [GHSA-47p6-69vm-vw6v](https://github.com/advisories/GHSA-47p6-69vm-vw6v) / CVE-2026-9495 | `@koa/router` | router prefixes with path parameters could silently drop middleware from the execution chain | Review route-prefix patterns where auth, rate-limit, or sanitizer middleware is attached to parameterized routers; proof is a middleware decision matrix, not broad endpoint fuzzing. |
| [GHSA-wpqm-4gwx-w843](https://github.com/advisories/GHSA-wpqm-4gwx-w843) / CVE-2026-44598 | Apache Shiro Jakarta EE saved-request cookie | post-login redirect state could be forged into a server-side HTTP GET | Treat encrypted/signed return-state cookies as SSRF and open-redirect inputs when the server later dereferences or redirects from them. |
| [GHSA-fcvm-3cpj-f9qx](https://github.com/advisories/GHSA-fcvm-3cpj-f9qx) / CVE-2026-43827 | Apache Shiro default sessions | pre-auth session IDs persisted across successful login | Session-fixation testing remains valuable on frameworks that do not rotate IDs at privilege change; prove only with your own two-browser lab sessions. |
| [GHSA-7jcp-v9w4-wjmg](https://github.com/advisories/GHSA-7jcp-v9w4-wjmg) / CVE-2026-7374 | KubeVirt `virt-handler` VM console sockets | namespace editor control over console-socket paths could follow symlinks into host Unix sockets | VM platform assessments should include symlink/canonicalization checks for host-mounted socket paths; stop at canary socket reachability evidence. |
| [GHSA-qqw8-7c2r-jxch](https://github.com/advisories/GHSA-qqw8-7c2r-jxch) / CVE-2026-48791 | `sigstore-java` 2.0.0 bundle verification | Rekor `integratedTime` was not bound to Fulcio certificate validity | Supply-chain validation should include stale/future-time bundle negative controls, especially where Java tooling gates artifact promotion. |
| [GHSA-gq7g-vg2q-jvq3](https://github.com/advisories/GHSA-gq7g-vg2q-jvq3) / CVE-2026-42782 | Apache Syncope Groovy implementations | admin-authored Groovy static initializers reached non-sandboxed execution | Identity-platform extension points are code-execution surfaces; prove with inert class initializers in a lab realm only. |
| [GHSA-vr35-jm2f-8wg2](https://github.com/advisories/GHSA-vr35-jm2f-8wg2) / CVE-2026-42797 | Apache Syncope derived-schema JEXL | schema expressions could expose sensitive user data to admins with read entitlements | Test expression languages for data-scope expansion with seeded canary attributes, not real user secrets. |

Adjacent updated advisories for Kahi supervisor permissions, Dolibarr installer RCE, TCC-TRANSACTION Fastjson deserialization, Blitz XSS, vLLM resource shutdown, duplicate gitoxide metadata, Shiro cookie `Secure` flag hygiene, and Hermes dashboard project-plugin comparison were processed without promotion here because they were either generic hygiene, duplicate/legacy summaries, sparse local-only details, or did not add a distinct replayable operator workflow beyond existing pages.

## Replayable validation boundaries

### Express/Cedar and Koa parser-drift harness

- Preconditions: owned Express or Koa app, route/action map, two disposable roles, and no production data.
- Build a table of route patterns and middleware expected to run for each method/path. Include collection routes, parameterized routes, and routers with prefixes such as `/:tenant` or `/:id`.
- Send paired requests that differ only in query string, trailing slash, encoded separator, and prefix parameter placement.
- Positive evidence is an authorization or middleware decision that maps to one route while the application handler executed another.
- Keep response bodies synthetic. Redact real user records, tokens, and tenant identifiers.

### Shiro saved-request and session-fixation harness

- Preconditions: disposable Shiro application using affected `shiro-jakarta-ee` or default session configuration, owned credentials, and a canary callback host.
- For saved-request testing, create or modify only your own pre-login saved-request cookie/state so the post-login flow attempts a harmless canary URL or redirect target.
- Positive evidence is a server-side callback to the canary host or a browser redirect derived from attacker-controlled saved-request state.
- For fixation testing, start an anonymous session in browser A, authenticate using the same session ID, and compare whether the ID rotated on login.
- Do not target admin consoles, internal metadata services, production SSO, or other users' sessions.

### KubeVirt console-socket symlink harness

- Preconditions: lab OpenShift/KubeVirt cluster, namespace-scoped edit rights, disposable VM, and a canary Unix socket or marker path approved by the cluster owner.
- Attempt to replace only the VM console socket path in the lab namespace with a symlink to the canary socket path.
- Trigger the normal console-connect flow and record whether `virt-handler` follows the symlink using privileged host context.
- Stop at reachability or connection-attempt evidence. Do not connect to CRI-O, containerd, kubelet, Docker, or other privileged production sockets.

### Sigstore Java integrated-time negative control

- Preconditions: isolated Java verification runner, `sigstore-java` 2.0.0 and a fixed version, plus the published sigstore-conformance future-time test bundle or an equivalent synthetic bundle.
- Verify the same artifact and bundle pair with the affected and fixed versions.
- Positive evidence is an affected verifier accepting a bundle whose Rekor integrated time should fall outside the Fulcio certificate validity window.
- Do not use real stolen keys, private build material, or production release artifacts as proof.

### Syncope Groovy/JEXL canaries

- Preconditions: lab Syncope realm, disposable admin roles matching the advisory preconditions, synthetic user attributes, and no live identity data.
- For Groovy implementations, use a static initializer that writes an inert marker or logs a canary string only in the lab.
- For derived-schema JEXL, seed a fake sensitive-looking user attribute and prove whether an expression exposes it to a role that should not see it directly.
- Negative controls: fixed Syncope versions, sandboxed static initializers, expression allowlists, and per-attribute authorization checks at expression evaluation time.

## Reporting notes

- Lead with the precise parser or trust-boundary mismatch: **auth route vs app route**, **saved request vs server fetch**, **namespace VM console vs host socket**, **bundle time vs certificate validity**, or **identity extension vs sandbox/data scope**.
- Include package versions, exact route/action patterns, role used, expected decision, observed decision, and a fixed-version negative control.
- Keep proof artifacts harmless: canary URLs, synthetic routes, fake accounts, lab sockets, inert Groovy/JEXL markers, and public conformance bundles.
