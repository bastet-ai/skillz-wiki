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

## October 1 21:3xZ follow-up: the rest of the wave — module-level primitives (folded)

The same 18:32Z advisory train carried a second tier of httpd 2.4.0–2.4.68 module defects that landed in the updated feed at 21:33Z. Same invariant as this page — **the module you enabled is a separate implementation with its own parser, buffer, and trust assumptions** — but different sinks:

| Advisory | CVE | Module | Boundary |
| --- | --- | --- | --- |
| [GHSA-f5cw-5j88-wxxc](https://github.com/advisories/GHSA-f5cw-5j88-wxxc) | CVE (9.8) | mod_rewrite | **Use-after-free in `mod_rewrite` lookahead** (`%{LA-U:HTTP:...}`) — the lookahead re-enters the filter chain for an internal sub-request and the shared request state lifecycle breaks, same shape as this page's digest/h2 findings |
| [GHSA-f6c9-29xf-9j37](https://github.com/advisories/GHSA-f6c9-29xf-9j37) | 7.5 | mod_vhost_alias | **Stack overflow via `Host` header >8192 bytes** when `VirtualDocumentRoot` uses a hostname format specifier and `LimitRequestFieldSize` is raised — remote unauthenticated DoS/possible code exec |
| [GHSA-6wv6-863r-87j4](https://github.com/advisories/GHSA-6wv6-863r-87j4) | 7.5 | mod_proxy_ftp | **Forward proxy opens a data connection to an arbitrary third-party host** from a crafted FTP PASV reply — an untrusted FTP server turns the proxy into an SSRF/port-scanner pivot |
| [GHSA-9fgx-g8xr-w8vf](https://github.com/advisories/GHSA-9fgx-g8xr-w8vf) | 7.5 | mod_proxy_uwsgi | **Response smuggling** via a crafted uwsgi response containing `Transfer-Encoding` (2.4.30+) |
| [GHSA-cr6f-pjrc-7rw2](https://github.com/advisories/GHSA-cr6f-pjrc-7rw2) | 5.3 | mod_userdir | **Path equivalence `/./`** with absolute non-wildcard `UserDir` — canonicalization differential at a file-existence gate |
| [GHSA-rxhx-8qf3-fc8h](https://github.com/advisories/GHSA-rxhx-8qf3-fc8h) | 3.7 | mod_cgi | Internal redirects **from** CGI execute the redirect *target* as CGI too (target must be in a CGI-enabled dir with no mime-recognized extension) |
| [GHSA-p249-893m-q7j8](https://github.com/advisories/GHSA-p249-893m-q7j8) | 5.3 | mod_dav_fs | `GET` the `.DAV` state directory to read **WebDAV dead properties of resources you cannot author** |

Durable axes from the second tier:

1. **`Host` is a memory-safety input, not just a routing string.** The vhost_alias overflow is triggered by the request's own `Host` header once `VirtualDocumentRoot` interpolates it. Add an oversized-Host probe (e.g. 9 KB `Host`) to any httpd recon pass on hosts where `LimitRequestFieldSize` has been raised — acceptance vs 400/413 vs worker death is a black-box configuration oracle. Prove reachability only; never chase the write.
2. **Any module that parses a peer-supplied address opens a pivot.** The PASV-reply flaw is the FTP twin of every "server names the connect destination" bug: in forward-proxy configs your *outbound* destination is chosen by the remote server's payload. If an authorized scope includes an httpd forward proxy with FTP enabled, connect it only to owned servers and record whether a crafted PASV address produces an outbound connection to your listener — that single proof is the finding.
3. **Lookahead/rewrite re-entrancy is auth-state lifecycle in a different costume.** `%{LA-U:...}` spawns an internal sub-request that shares request state; same test discipline as the digest race: sub-request-bearing rewrite rules on just-patched builds deserve re-run batteries, and 5xx only-when-a-specific-RulePattern-fires is the reachability signal.
4. **Response-side parser differentials exist below HTTP/1.1 framing too.** The uwsgi adapter trusts `Transfer-Encoding` inside the backend response — when a target fronts uwsgi/AJP/FCG variants, run the desync canary battery against the *backend protocol*, not just the client-facing leg.
5. **`/./` and `.DAV` are cheap recon strings.** Append `/./` segments to userdir-style paths and `GET /.DAV/` (or `GET <dir>/.DAV/`) on any WebDAV-visible route: an equivalence leak or dead-property disclosure is a same-origin, non-invasive first-touch check.

## Tracked, not published from the same wave

- Zod ≤4.6.5 uncapped array-issue accumulation OOM (CVE-2026-54404) — availability-only validation-library DoS; revisit if an early-termination oracle emerges.
- jackson-dataformats-binary Smile parser never invokes `StreamReadConstraints.validateNameLength()` (CVE-2026-68496) — constraint-coverage drift class (same shape as the Oct 1 guard-coverage page: the configured limit exists, one code path never calls the validator); no operator sink beyond DoS yet.
- TP-Link TL-WR841N authenticated IPv6-gateway command injection (CVE-2026-102294) — admin-auth router cmdi, single-product, class already covered.
