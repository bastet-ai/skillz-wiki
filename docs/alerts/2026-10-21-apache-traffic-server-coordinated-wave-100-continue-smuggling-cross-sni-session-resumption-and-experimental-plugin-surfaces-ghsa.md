# Apache Traffic Server coordinated wave: `Expect: 100-continue` smuggling both directions, cross-SNI session resumption mTLS bypass, and experimental plugins as unauthenticated surface

**Published:** 2026-10-21 21:32Z coordinated GHSA dump (fixes in ATS 9.2.16 / 10.1.5 / 10.2.1; bands below per leg).
**Audience:** anyone proxying traffic through ATS — CDN edges, enterprise forward/reverse proxies, cache tiers. Operator focus: what to probe on an ATS front, and what the wave teaches generically.

This is the second big ATS wave (the July 29 multi-protocol legs live on the [June 11 Undertow proxy-parser page](2026-06-11-undertow-proxy-parser-request-smuggling-boundary-ghsa.md)); the vendor shipped ~15 advisories in one minute. Four are critical. The durable content: `Expect: 100-continue` shows up as a smuggling primitive in *both* directions, TLS session state leaks identity across virtual hosts and across pooled origins, and three "experimental" plugins are unauthenticated attack surface in their default configuration.

## Advisory inventory

| GHSA / CVE | Sev | Leg |
|---|---|---|
| [GHSA-2g9h-67x8-9xr9](https://github.com/advisories/GHSA-2g9h-67x8-9xr9) / CVE-2026-111816 | critical | Malformed 302 forwarded: a `Transfer-Encoding: chunked` carve-out bypassed the parse-error rejection path, so a response two peers can read differently is stored and served — cache poisoning + response-framing desync. 8.x/9.0–9.2.15, 10.0–10.2.0 |
| [GHSA-4h97-h3mf-j6w7](https://github.com/advisories/GHSA-4h97-h3mf-j6w7) / CVE-2025-31699 | critical | Origin connection returned to the shared pool while the origin still waits on a declared-but-incomplete request body (incl. `Expect: 100-continue`): the origin reads a *later* request on that pooled connection as leftover body → smuggle past ATS access controls, disrupt other users, poison cache. 8.0.0–10.2.0 |
| [GHSA-98jq-8c4p-7mh6](https://github.com/advisories/GHSA-98jq-8c4p-7mh6) / CVE-2026-111811 | critical | Experimental `tsmemcache` plugin: unauthenticated network read, write, and delete of the shared proxy cache. 8.0.0–10.2.0 |
| [GHSA-c2v6-rh8p-xq4c](https://github.com/advisories/GHSA-c2v6-rh8p-xq4c) / CVE-2026-111813 | critical | Experimental `magick` plugin: unauthenticated client controls ImageMagick `convert` arguments in the default (unsigned) configuration. 8.0.1–10.2.0 |
| [GHSA-5vqp-jf47-frjg](https://github.com/advisories/GHSA-5vqp-jf47-frjg) / CVE-2025-55702 | high | POST with `Expect: 100-continue` where the origin answers before reading the body: ATS parses the unread body left on the *client* connection as the next request → attacker behind a connection-sharing front-end smuggles requests and desyncs responses for other users. 8.0.0–10.2.0 |
| [GHSA-h35r-68fc-8f5m](https://github.com/advisories/GHSA-h35r-68fc-8f5m) / CVE-2026-111815 | high | TLS session resumed **across SNI virtual hosts** without re-verifying the client certificate required by the resumed host's `verify_client STRICT` policy. 8.0.0–10.2.0 |
| [GHSA-h7pm-58x7-4q68](https://github.com/advisories/GHSA-h7pm-58x7-4q68) / CVE-2026-111814 | high | Default outbound session-sharing reuses a pooled TLS session authenticated with one client certificate for a transaction configured to present a **different** one. 9.0.0–10.2.0 |
| [GHSA-hq3r-f7fj-4pwj](https://github.com/advisories/GHSA-hq3r-f7fj-4pwj) / CVE-2026-111812 | high | `origin_server_auth` plugin lets a client force signing of **attacker-chosen AWS request headers** under the proxy's own credentials. 8.0.0–10.2.0 |
| [GHSA-cw25-xpjm-pj8v](https://github.com/advisories/GHSA-cw25-xpjm-pj8v) / CVE-2026-111805 | high | Truncated HTTP/2 `Content-Length` value exhausts an HTTP/1 origin's worker pool (h2→h1 translation). 8.0.0–10.2.0 |
| [GHSA-93mv-pcxw-4fpr](https://github.com/advisories/GHSA-93mv-pcxw-4fpr) / CVE-2026-111808 | high | Malformed padded HTTP/2 DATA frame, same worker-pool exhaustion shape. 8.0.0–10.2.0 |
| [GHSA-286j-qmf9-6g9f](https://github.com/advisories/GHSA-286j-qmf9-6g9f) / CVE-2026-111804 | high | Experimental `wasm` plugin: use-after-free in transaction-close handler + unvalidated guest-supplied metric IDs forwarded to the internal stats API. 10.0.0–10.2.0 |
| [GHSA-fx98-vw52-fjmw](https://github.com/advisories/GHSA-fx98-vw52-fjmw) / CVE-2026-111810 | high | One unthrottled diagnostic log line per stripped internal `@` header: many `@`-prefixed headers make the proxy write far more log data than the request contains. Bands 9.2.15, 10.1.4, 10.2.0 |
| [GHSA-vv7x-cx95-rcmh](https://github.com/advisories/GHSA-vv7x-cx95-rcmh) / CVE-2026-112381 | high | NULL-deref crash: POST torn down via half-close while a chunked origin response is reparsed from a reentrant write-ready callback — **a timing race introduced by the CVE-2021-32564 flow-control backports**. Bands 9.2.15, 10.1.4, 10.2.0 only |
| [GHSA-hwgh-j4gj-qv24](https://github.com/advisories/GHSA-hwgh-j4gj-qv24) / CVE-2026-111809 | medium | Request smuggling via `HEAD` requests carrying `Content-Length` or `Transfer-Encoding`. 8.0.0–10.2.0 |
| [GHSA-8jj5-9h2j-2r96](https://github.com/advisories/GHSA-8jj5-9h2j-2r96) / CVE-2026-111817 | medium | Chunked passthrough stalls when trailers are removed (`proxy.config.http.drop_chunked_trailers`, **on by default in 10.x**): ATS waits for trailer bytes it already dropped, until timeout. 8.1.11, 9.2.5–9.2.15, 10.x |

## What an operator does with this

### 1. The `Expect: 100-continue` battery, both directions

Two independent critical/high legs are the same feature mis-sequenced on opposite legs of the proxy:

- **Ingress side** (5vqp): send `POST` + `Expect: 100-continue` with a body the *front-end* considers sent but the origin answers-before-reading — the unread body bytes get parsed by ATS as the next request on your own connection.
- **Egress side** (4h97): get an origin into wait-for-body state, make ATS return that origin connection to the shared pool — your leftover body becomes the *next tenant's* request as far as that origin is concerned.

Probe pattern on any ATS (and by extension any chained-proxy deployment): one connection, one mutation, four evidence points (client bytes / ATS ingress view / ATS egress bytes / origin view) — the four-recorder lab from the June 11 page applies unchanged. Variants to run: `Expect: 100-continue` with zero body, short `Content-Length`, chunked body abandoned after first chunk, `Expect` + `TE` mixtures, HEAD-with-body variants (hwgh's CL/TE-on-HEAD leg belongs to the same sweep — HEAD is the overlooked method in most smuggling suites). Cache-poisoning proof should target a harmless route with a per-request unique canary header echoed, never a real user route.

Also note the wave's transport-parity reminder: the two h2→h1 resource-exhaustion legs (cw25, 93mv) prove ATS's HTTP/2 ingress parser and HTTP/1 egress serializer are separate implementations with separate accounting. If Alt-Svc is advertised, run the whole framing battery over h2 too — truncation and padding classes live in the translation.

### 2. TLS session state is an identity carrier — in both directions

- h35r: an inbound session established at a no-mTLS SNI host can be resumed at a `verify_client STRICT` host **without the client cert being re-requested or re-verified**. The session ticket/cache is the authorization input, and it crossed virtual-host boundaries.
- h7pm: the reverse direction — ATS's outbound pool reuses one origin-side mTLS session when the transaction was configured to present a different client certificate. Upstream identity confusion by pool default.

Generic rules: (a) after authenticating anywhere on a multi-vhost endpoint, attempt session resumption (`openssl s_client -sess_out/-sess_in`) at every stricter sibling host — client-cert-required routes reached without a cert is a positive finding on any TLS terminator, not just ATS; this is the same family as the Oct 14 NGINX `ssl_session_cache` forgery leg (forgeable shared sessions bypassing mTLS) — one more entry in the "session state is authorization input" list; (b) on egress side, if you can influence which upstream ATS connects to, check whether your request lands on a pooled session that carries a different client certificate (response-side identity signals from the origin — cert-dependent routes — are the oracle).

### 3. Experimental plugins are the softest unauthenticated surface

Three of the four criticals/highs are plugins flagged experimental, and in default configuration they are unauthenticated:

- `tsmemcache`: full read/write/delete of the shared cache over the network with no auth (98jq) — direct cache-poisoning and content-removal primitive against the whole edge.
- `magick`: attacker controls ImageMagick `convert` argv in the default *unsigned* config (c2v6) — the launcher-argument-injection shape again (third-generation sibling of the Oct 21 Pillow Ghostscript leg on the Sept 20 media page: `-`-prefixed option, `@`-file arguments; `-dSAFER`-style interpreter hardening does not guard the argv parser).
- `wasm`: guest-supplied metric IDs passed unvalidated into the internal stats API + UAF (286j).

Fingerprint pass on any ATS target: enumerate enabled plugins (config-derived behavior, plugin-specific URL/header reactions), and treat every experimental one as in-scope unauthenticated surface first. `magick`'s "default (unsigned)" note is the recurring *fail-open-by-default toggle* pattern — the secure mode exists and is off.

### 4. `origin_server_auth`: the proxy as a signing oracle

hq3r: a client can force the proxy to sign **attacker-chosen AWS headers** with the proxy's own credentials. Generic axis: any edge plugin that signs, stamps, encrypts, or decorates requests with proxy-held credentials must bind *which fields* it will sign — if the client picks the payload, the plugin is a credential oracle for whatever the signature is honored for (S3 requests, origin auth headers, service-to-service trust). Probe: request a route that triggers signing and try to steer additional signed headers; diff the origin-received signed set against the request you sent.

### 5. Fix-backports create bugs; newest-but-one band is the fragile one

vv7x's race was **introduced by the CVE-2021-32564 flow-control backports** and only exists in 9.2.15 / 10.1.4 / 10.2.0 — the latest-but-one releases. fx98's log amplification likewise lands in that band. Fingerprinting lesson: an exact version match on the *newest fixed-but-one* line is a hint the deployment sits on freshly backported code; security-patch backport waves are bug generators, and a "fully patched except this month" fleet can be more broken than an older one. The DoS legs (fx98, 8jj5 trailer-stall) are also low-noise degradation primitives where engagement rules allow availability testing — 8jj5 is default-on in 10.x, so the check is just: chunked passthrough + trailer-bearing response through ATS 10.x hangs.

## Validation boundaries

Lab or customer-approved ATS only. Smuggling proofs on owned origins with canary routes; cache-poison proofs on synthetic cache keys; never desync real user sessions or rewrite production cache objects. Plugin testing against disposable ATS instances, not shared edges. mTLS probes with client certs you own.

## Related pages

- [June 11 Undertow proxy-parser smuggling page](2026-06-11-undertow-proxy-parser-request-smuggling-boundary-ghsa.md) — July 29 ATS wave (h2 ingress/TE carry, chunk-framing split, header truncation aliases) and the four-recorder ATS lab.
- [Oct 14 NGINX coordinated wave](2026-10-14-nginx-coordinated-wave-ssi-aio-uaf-map-alias-overflows-http3-injection-mtls-session-forgery-and-ingress-header-relay-ghsa.md) — `ssl_session_cache` forgery sibling for the session-state-as-authorization rule.
- [Sept 20 media-pipeline page](2026-09-20-media-pipeline-edge-surfaces-filename-shellout-metadata-xxe-author-template-rce-ghsa.md) — Ghostscript/Pillow launcher argv-injection lineage for the `magick` leg.
