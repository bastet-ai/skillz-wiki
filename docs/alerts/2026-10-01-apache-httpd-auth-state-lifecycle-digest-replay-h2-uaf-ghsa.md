# Apache HTTP Server auth-state lifecycle: Digest capture-replay, concurrent-request UAF, and h2 session reuse (2.4.0–2.4.68)

Source: GitHub advisories published 2026-10-01 against Apache HTTP Server (fixed 2.4.69). Related pages: [Sept 21 auth-method precedence page](2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md), [Aug 26 Tomcat auth/parser batch](2026-08-26-tomcat-authorization-auth-parser-boundary-batch-ghsa.md).

Why this is durable: httpd 2.4.x is deployed behind a huge share of frontiers, and this wave is about **authentication state that lives in server memory with a lifecycle** — nonces, nonce-counters, shared-memory entries, per-session buffers. Every one of these items gives a *black-box testable* property: you can detect the vulnerable configuration and prove the boundary from the client side without an exploit.

## The four advisories

| Advisory | CVE | Module | Boundary |
| --- | --- | --- | --- |
| [GHSA-x3h4-7828-fv9v](https://github.com/advisories/GHSA-x3h4-7828-fv9v) | CVE-2026-73636 | mod_auth_digest | **Authentication bypass by capture-replay**: a MITM replays captured Digest credentials via crafted requests that trigger garbage collection of the client's shared-memory entry when `AuthDigestNonceLifetime` is 0 |
| [GHSA-gr5c-77fq-wx32](https://github.com/advisories/GHSA-gr5c-77fq-wx32) | CVE-2026-73637 | mod_auth_digest | **Use-after-free**: unauthenticated remote client causes *authentication state corruption* via **concurrent** Digest requests when `AuthDigestNcCheck` is enabled or `AuthDigestNonceLifetime` is 0 |
| [GHSA-w59m-qjff-crxx](https://github.com/advisories/GHSA-w59m-qjff-crxx) | CVE-2026-57941 | mod_http2 | **Use-after-free** via shared `session->bbtmp` re-entrancy (2.4.0–2.4.68) |
| [GHSA-qp6v-989p-mw9v](https://github.com/advisories/GHSA-qp6v-989p-mw9v) | CVE-2026-59797 | mod_ssl | Improper privilege management via `SSLRequire` and file-related expressions |

## Durable axes

1. **Digest auth state is a configuration-visible oracle.** The vulnerable preconditions (`AuthDigestNcCheck On`, `AuthDigestNonceLifetime 0`) are *probeable from outside*: replay the same nonce with the same `nc` and watch whether it's accepted (NC check off/weak), reuse a nonce long after issuance (lifetime 0 → stale nonces accepted, which is exactly the replay precondition). Add a Digest-auth probe to any recon pass that sees `WWW-Authenticate: Digest`: challenge parse → nonce lifetime test → nc-increment test → concurrent-issue test. The replay bypass itself needs a MITM position, so report the *probeable configuration* (stale nonce + no nc enforcement) as the finding, which is the same precondition set.
2. **Concurrency is an auth-state attack, not just a DoS attack.** The UAF is reached by *concurrent* Digest requests corrupting authentication state — an unauthenticated client. The class rule (join: session-cache OTP counters, Keycloak session-restart marker wipe): when auth state is keyed per-client in shared memory and mutated per-request, race the requests. Black-box signal: auth results that flip for the *same* valid credential under parallel load, or 5xx on `/` only under concurrent 401-challenge pressure. Prove only "authentication state corruption" (wrong-code accepted / correct-code rejected under race) on authorized targets — the UAF itself is crash territory, lab builds only.
3. **Protocol-layer UAF on just-patched builds.** The h2 `session->bbtmp` re-entrancy UAF sits in the version range that has been "current" for years; same lesson as the Tomcat HTTP/2 fix-regression entry: after any httpd mod_http2 CVE cycle, re-run the raw-byte h2 battery against the *new* build, because shared session buffers are exactly where fixes introduce re-entrancy bugs. Frame h2 memory-safety as reachability evidence (does the server accept malformed stream interleaving at all?), never crash public frontiers.
4. **`SSLRequire` expression gaps = mTLS policy that doesn't apply.** File-related expressions in `SSLRequire` privilege mismanagement means authorization decisions written in `mod_ssl` expressions can evaluate against the wrong object. Operator rule: whenever a target uses `SSLVerifyClient optional` + `SSLRequire` (soft-fail mTLS, the pattern behind this page's Tomcat realm first-wins sibling), test the full decision matrix: no cert / valid cert / revoked-or-foreign cert against each protected location, and diff which locations authorize — the expression-evaluation bug shows up as an unexpected allow on one leg.

## Validation boundaries

Authorized targets only. Non-invasive proofs first: Digest configuration probing (nonce reuse, nc replay), mTLS decision tables, version banner (`Server:` header + protocol feature probes). The Digest UAF and h2 UAF are crash/memory-corruption primitives — reproduce only against lab httpd builds you own, with the exact advisory configuration (`AuthDigestNcCheck On` / `AuthDigestNonceLifetime 0`), and never fuzz production frontiers with concurrent-state-corruption traffic. Capture the 401-challenge parameters as evidence; never collect real user credentials.

## Tracked, not published from the same wave

- Zod ≤4.6.5 uncapped array-issue accumulation OOM (CVE-2026-54404) — availability-only validation-library DoS; revisit if an early-termination oracle emerges.
- jackson-dataformats-binary Smile parser never invokes `StreamReadConstraints.validateNameLength()` (CVE-2026-68496) — constraint-coverage drift class (same shape as the Oct 1 guard-coverage page: the configured limit exists, one code path never calls the validator); no operator sink beyond DoS yet.
- TP-Link TL-WR841N authenticated IPv6-gateway command injection (CVE-2026-102294) — admin-auth router cmdi, single-product, class already covered.
