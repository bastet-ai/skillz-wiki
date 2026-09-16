# Http4s Ember and Traefik parser, header, and route authority boundaries (19 GHSAs)

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-09-15 (waves published 2026-09-10T20:25Z–2026-09-15T20:01Z).

Two reviewed-parser clusters landed the same week and share one operator rule: **a front-end security decision is only as strong as the framing, header-grammar, and path-normalization agreement between the proxy layer and the backend parser.** Both Http4s Ember (Scala HTTP server/client) and Traefik published advisories where the security-relevant view of a request diverges from what the backend actually receives.

## Advisory table

Http4s Ember (`org.http4s`, fixed `0.23.35` / `1.0.0-M47`):

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-8h4c-x2wg-6xp8](https://github.com/advisories/GHSA-8h4c-x2wg-6xp8) | CVE-2026-69204 | critical | CL.TE: `Transfer-Encoding` + `Content-Length` accepted instead of framed as an error (RFC 9112 §6.1) → smuggling behind CL-strip-and-forward intermediaries |
| [GHSA-9998-894r-fwvr](https://github.com/advisories/GHSA-9998-894r-fwvr) | CVE-2026-69205 | high | TE.CL/TE.0: `Transfer-Encoding` value matched by **case-sensitive substring** (`contains("chunked")`) — `Transfer-Encoding: Chunked` frames by Content-Length while a compliant intermediary frames by chunked |
| [GHSA-jrpm-956j-96jg](https://github.com/advisories/GHSA-jrpm-956j-96jg) | CVE-2026-69216 | medium | TE.TE: chunk-size token accepts whitespace and `+`/`-` sign outside RFC 9112 `1*HEXDIG` grammar |
| [GHSA-crq5-92j2-j7wv](https://github.com/advisories/GHSA-crq5-92j2-j7wv) | CVE-2026-69201 | medium | `ResourceService`/`WebjarService` reject exact `.`/`..` segments only after per-segment decode — `%2F..%2F` smuggles traversal past the filter (and `%5C` on Windows) |
| [GHSA-grh8-3p95-f9rr](https://github.com/advisories/GHSA-grh8-3p95-f9rr) | CVE-2026-69215 | medium | Client `CookieJar` attaches cookies by **unanchored substring** host test — cookie for `example.com` sent to `evilexample.com` |
| [GHSA-wv64-j4fq-5f9x](https://github.com/advisories/GHSA-wv64-j4fq-5f9x) | CVE-2026-69214 | medium | `CookieJar` trusts server-supplied `Domain` verbatim (no domain-match, no public-suffix check) → cross-domain cookie plant/fixation |
| [GHSA-9xww-74xv-gjfp](https://github.com/advisories/GHSA-9xww-74xv-gjfp) | CVE-2026-69206 | medium | `DigestAuth` stores `lastNc + 1` instead of the accepted `nc` — captured Authorization headers replay multiple times |
| [GHSA-fm4g-76c9-7w69](https://github.com/advisories/GHSA-fm4g-76c9-7w69) | CVE-2026-69208 | high | DigestAuth nonce map grows unbounded (tracked, availability) |
| [GHSA-gq9p-f254-h286](https://github.com/advisories/GHSA-gq9p-f254-h286) | CVE-2026-88975 | high | HTTP/2 buffers a frame's declared payload before checking `SETTINGS_MAX_FRAME_SIZE` (tracked) |
| [GHSA-cp4q-fqw9-4hf6](https://github.com/advisories/GHSA-cp4q-fqw9-4hf6) | CVE-2026-69218 | high | HTTP/2 unbounded continuation-frame accumulation (tracked) |
| [GHSA-6m4x-pp6q-5jmm](https://github.com/advisories/GHSA-6m4x-pp6q-5jmm) | CVE-2026-69202 | high | HTTP/2 unbounded inbound body buffering (tracked) |
| [GHSA-8f3q-3jmv-7prw](https://github.com/advisories/GHSA-8f3q-3jmv-7prw) | CVE-2026-69213 | high | HTTP/2 unbounded outbound frame queue driven by cheap control frames (tracked) |
| [GHSA-9vwc-pc8p-253q](https://github.com/advisories/GHSA-9vwc-pc8p-253q) | CVE-2026-69203 | high | HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` not enforced (tracked) |

Traefik (fixed `3.7.12`/`3.7.13` and `2.11.56`/`2.11.57`) — follow-up records on the existing [Traefik route, transport, and namespace authority boundaries](2026-08-05-traefik-route-transport-namespace-boundaries-ghsa.md) page:

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-f52w-8j3h-j724](https://github.com/advisories/GHSA-f52w-8j3h-j724) | CVE-2026-88009 | high | **Rootless (opaque) HTTP/1 request-target**: Go parses `GET http:http://internal/admin` into `URL.Opaque` with empty `Path`; router, path sanitization, `forwardAuth` path scoping, and access logs all see `/`, while the proxy forwards the original target byte-for-byte to the backend |
| [GHSA-w4v4-9rw7-5326](https://github.com/advisories/GHSA-w4v4-9rw7-5326) | CVE-2026-88008 | high | Client `Upgrade: h2c` + `HTTP2-Settings` forwarded; a backend that answers `101` puts Traefik into a raw byte tunnel that bypasses routers and the entire middleware chain |
| [GHSA-v67p-phpq-fc8x](https://github.com/advisories/GHSA-v67p-phpq-fc8x) | CVE-2026-88004 | high | Entrypoint header sanitization (`aliasHeadersStrategy`, `underscoreHeadersStrategy`, `forwardedHeaders` stripping) scans `req.Header` only, never `req.Trailer` — spoofed trusted headers smuggled as chunked/HTTP2 trailers |
| [GHSA-qqjf-53cj-pwvv](https://github.com/advisories/GHSA-qqjf-53cj-pwvv) | CVE-2026-88007 | critical | HTTP/3 path never initializes the connection-scoped backend transport holder, so Kerberos/NTLM backends share one connection-bound transport across frontend connections → cross-user credential binding reuse |
| [GHSA-rf44-j88r-hh8c](https://github.com/advisories/GHSA-rf44-j88r-hh8c) | CVE-2026-88011 | medium | ForwardAuth identity spoofing via dot-form header alias (`X.Auth.User` vs `X-Auth-User`): Go canonicalizes dashes only, CGI/WSGI/PHP/NGINX backends collapse all spellings to one variable |

Adjacent (tracked, no operator page): [GHSA-5hq8-qhww-jm7q](https://github.com/advisories/GHSA-5hq8-qhww-jm7q) libp2p-quic remote panic via certificate-expiry race during QUIC handshake.

## Why this is worth an operator page

- **These are the exact primitive grammars every smuggling engagement re-derives from scratch.** Ember documents three independent framing divergences (CL.TE, TE.CL via case-sensitivity, TE.TE via chunk-size lenience) and Traefik adds two *request-grammar* divergences (opaque request-target, trailer-sourced headers) that are rarely in standard wordlists.
- **The rootless request-target is the highest-value single record**: routing and path-scoped authz evaluated against a normalized `/` while the backend receives the raw target is a router/authz bypass channel, not just a cache-poisoning curiosity.
- **Trailer-sourced trusted headers are an under-tested surface on any proxy** — the sanitizer iterates the header map, the backend (or a framework that merges trailers) sees them as fields.
- **Header-name alias collapsing (dot/underscore/dash)** is the same parser-differential axis as the August 5 Traefik underscore-alias records; backends that derive variables from names collapse spellings the proxy treats as distinct.

## Validation workflow (authorized scope only)

!!! warning "Lab backends and single-connection canaries only"
    Test only against owned stacks in authorized scope. Use single-connection, self-contained canaries (one request, one response marker), never cross-user desync, cache poisoning of shared entries, or auth-boundary mutation on production. Record raw bytes on both sides of the proxy.

1. **Framing differential harness.** For each origin behind each intermediary, send one connection with: `Transfer-Encoding: chunked` + `Content-Length` (CL.TE); `Transfer-Encoding: Chunked` (case), `chUnKeD`, obfuscating whitespace variants (TE.CL); `+5`, ` 5 `, signed chunk sizes (TE.TE); and the opaque-form request-target `GET http:http://<owned-vhost>/admin HTTP/1.1`. Compare the two views: what the front normalizes/routes vs the raw target/body the backend echoes from an owned no-op route.
2. **Trailer smuggle probe.** Send a chunked request whose final chunk carries `X-Forwarded-Prefix` / `X_Auth_User` / `X.Auth.User` trailers; confirm whether the backend framework surfaces them as request headers or variables. Evidence is the echoed field name/value, not a privilege change.
3. **Static-route decode check.** Request `/%2F..%2F..%2F<canary>` and `%5C` variants against static handlers; prove only with synthetic classpath/resource canaries outside the configured base — never config files or key material.
4. **Client-side cookie jar audit** (for Scala services acting as SSRF-capable fetchers): verify domain-match anchoring with two owned hosts (`owned-a.example` vs `xowned-a.example`) and a server that answers `Set-Cookie: ...; Domain=owned-b.example`.
5. Report only framing/decision mismatch evidence with raw-byte captures; stop at the boundary.
