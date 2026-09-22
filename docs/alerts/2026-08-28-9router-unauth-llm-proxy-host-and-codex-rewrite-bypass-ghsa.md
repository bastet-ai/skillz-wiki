# 9router unauthenticated LLM-proxy access: Host-header spoofing and /codex rewrite bypass — operator validation

**Date reviewed:** 2026-08-28
**Advisories:** [GHSA-86m2-fcxq-5q7c / CVE-2026-55641](https://github.com/advisories/GHSA-86m2-fcxq-5q7c) (high), [GHSA-8gmq-j984-vp4r / CVE-2026-55638](https://github.com/advisories/GHSA-8gmq-j984-vp4r) (high). Both in `npm/9router` `<= 0.4.80` (fixed in `0.5.2`).

9router is an OpenAI/Anthropic-compatible LLM proxy that fronts the operator's **stored paid provider API keys**. Both findings bypass its auth gate, letting an unauthenticated remote attacker use the victim's provider credentials — and, in the first case, drive a server-side fetch. The durable pattern: **the authorization decision is made on a client-controlled field (Host header) or on the pre-rewrite request path, and the "local/trusted" exemption or the rewrite destination is not re-validated after the decision.**

## 1. Unauthenticated `/v1` proxy access via `Host`-header spoofing (GHSA-86m2-fcxq-5q7c)

9router's request guard (`src/dashboardGuard.js`, `isLocalRequest`) decides a request is "local" — and therefore **exempt from API-key auth on the `/v1` LLM proxy** — by reading the **client-controlled `Host` header**. Because 9router binds `0.0.0.0` by default (and the CLI misleadingly prints "localhost"), a remote unauthenticated attacker who can reach the port sends `Host: localhost` and is treated as local. In the default configuration (`requireApiKey` is absent from `DEFAULT_SETTINGS`, so the handler-side key check is skipped), this yields:

- **Open AI relay** — the proxy forwards the attacker's requests to AI providers using the **victim's stored paid API keys** (cost/quota theft, prompt-based data exfiltration through the victim's accounts).
- **Unauthenticated SSRF** — `/v1/search` with the built-in `noAuth` `searxng` provider takes its outbound fetch URL from the request body (`provider_options.baseUrl`), so the attacker drives a server-side fetch to any internal/cloud-metadata host and gets the JSON response reflected back.

Affected: `src/dashboardGuard.js` (`isLocalRequest`), `src/sse/handlers/{chat,search}.js`, `src/lib/db/repos/settingsRepo.js`, `cli/cli.js`. Distinct from the already-patched GHSA-fhh6-4qxv-rpqj (MCP-plugin RCE) and GHSA-xrrh-p7f2-27vm (legacy `<0.3.75` authz bypass).

## 2. Unauthenticated LLM proxy access via `/codex` rewrite auth bypass (GHSA-8gmq-j984-vp4r)

The API-key gate lives in the Next.js middleware and protects `/v1`, `/v1beta`, `/api/v1`, and `/api/v1beta` — but **not** `/codex`. 9router also defines a rewrite that maps `/codex/*` to the backend LLM endpoint `/api/v1/responses`. The middleware authorization decision is made on the **incoming request path before the rewrite is applied**. Because `/codex` is not in the middleware's protected LLM API prefix list, requests to `/codex/*` pass the gate unauthenticated and are later rewritten to the same backend used by `/api/v1/responses`:

| Component | File | Note |
| --- | --- | --- |
| Middleware authorization gate | `src/dashboardGuard.js` | Protects `/v1`, `/v1beta`, `/api/v1`, `/api/v1beta`, but **not** `/codex` |
| Rewrite configuration | `next.config.mjs` | Rewrites `/codex/:path*` to `/api/v1/responses` |
| LLM backend route | `src/app/api/v1/responses/route.js` | Dispatches rewritten requests to the LLM handler |

Result: an unauthenticated remote attacker reaches the LLM proxy through `/codex/*` and causes the server to make upstream provider calls using the operator-stored LLM provider credentials.

## Durable operator value

1. **A "local" exemption keyed off the `Host` header is an auth bypass.** Any middleware that treats loopback/localhost `Host` values as trusted — on a service that binds `0.0.0.0` — lets any remote peer self-declare as local. The fix has to decide locality from the **socket peer**, not a header. Probe: send `Host: localhost` (and `127.0.0.1`, `[::1]`) to an externally-reachable port and compare the auth decision.
2. **Auth-on-pre-rewrite path = bypass.** When an edge/framework rewrites a public path to an internal API and the auth gate runs on the *original* path, any public alias that maps onto a protected internal route is open. Enumerate the rewrite/alias table (`next.config.mjs` rewrites, nginx `location` → `proxy_pass`, Traefik `StripPrefix`/route aliases) and diff it against the auth-protected prefix list. Every rewrite destination not covered by the gate is a candidate.
3. **Default-no-key + default-0.0.0.0 = open relay.** A proxy that fronts paid credentials and defaults to "no API key required" plus "bind all interfaces" is an open relay out of the box. The `DEFAULT_SETTINGS` missing `requireApiKey` is the concrete instance; the heuristic is "does the default config require a key on the proxy path?"
4. **Reflecting the provider's response is an SSRF amplifier.** When the proxy reflects the upstream provider JSON back to the caller, a `provider_options.baseUrl`-driven fetch becomes a read-SSRF against internal/cloud-metadata. Probe with a benign internal URL and record the reflected response shape (don't target real metadata in production).

## Replayable validation (lab only)

Preconditions: an authorized lab 9router `<= 0.4.80` (or a patched `0.5.2` control), a disposable upstream provider key stored in the proxy, a lab internal callback host, and a redacting recorder. No production provider keys, no real metadata/internal services, no cost-generating provider calls beyond a single canary.

1. **Host-spoof bypass (GHSA-86m2-fcxq-5q7c).** From a non-loopback host, send `GET /v1/...` (or a minimal chat request) with `Host: localhost` and no API key. Positive: the proxy accepts it and makes an upstream call using the stored key. Negative control: the same request from loopback with the key, and the same request with a non-loopback `Host` (which should 401). Record the guard decision (accepted vs 401) and the upstream call (provider + redacted key presence), not the key value.
2. **SSRF leg (GHSA-86m2-fcxq-5q7c).** With the bypass active, `POST /v1/search` with the `searxng` provider and `provider_options.baseUrl` set to a lab callback. Positive: the lab callback receives the server-side fetch. Do not point it at cloud metadata or internal services in production.
3. **/codex rewrite bypass (GHSA-8gmq-j984-vp4r).** Send an unauthenticated request to `/codex/*` that maps to `/api/v1/responses`. Positive: the LLM handler executes an upstream call with the operator's key. Negative control: the identical request to `/api/v1/responses` directly (should 401) and the same `/codex/*` path on `0.5.2` (should 401 or be rewritten behind the gate).
4. **Default-posture check.** Confirm `requireApiKey` is absent from `DEFAULT_SETTINGS` and the listener binds `0.0.0.0` (the CLI prints "localhost" but binds all). Report the default config, not just the exploit.

Evidence to capture: the guard/rewrite source lines, the `Host`/path that flipped the auth decision, the upstream provider call with the redacted key, and the reflected/forwarded response shape. Redact all provider keys.

## Safe boundaries

- Authorized lab 9router only; disposable upstream key; lab callback host.
- No production provider keys, no cloud-metadata or internal-service SSRF, no cost-generating provider calls beyond a single canary, no credential exfiltration.
- Report the exact guard/rewrite line, the default no-key/all-interfaces posture, and the pre- vs post-rewrite (or spoofed-Host) differential with the patched-version negative control.

## September 22 follow-up: the same product, now spoofing the *IP* header (GHSA-5mj8-gf6m-fhw8 / CVE-2026-56681 high, GHSA-32gc-64m7-hj7v / CVE-2026-56682 medium)

9router `0.5.4` shipped two more findings that are the header-spoofing lesson retargeted from `Host` to a custom forwarding header, `X-9r-Real-Ip`:

- **Unauthenticated LLM API via spoofable `X-9r-Real-Ip`** ([CVE-2026-56681](https://github.com/advisories/GHSA-5mj8-gf6m-fhw8)): `isLocalRequest()` in `src/dashboardGuard.js` reads `X-9r-Real-Ip` to decide loopback origin; `canAccessPublicLlmApi()` skips API-key validation on `/api/v1/*` when "local". The header is only stripped/regenerated by the bundled `custom-server.js` wrapper — in deployment modes where traffic reaches Next.js directly, `X-9r-Real-Ip: 127.0.0.1` from any remote peer = unauthenticated use of the operator's stored provider keys (verified on `GET /api/v1/models`).
- **Login lockout bypass via the same header** ([CVE-2026-56682](https://github.com/advisories/GHSA-32gc-64m7-hj7v)): the progressive login lockout is keyed on `getClientIp()` which trusts `X-9r-Real-Ip`. Rotating a unique header value per request gives each attempt a fresh limiter bucket — reproduced live: fixed header locked out (429) after 5 attempts, rotating header produced unlimited 401s.

Durable additions to the sweep rules above:

1. **Enumerate the *custom* forwarding headers, not just the standards.** `X-Forwarded-For` and `X-Real-IP` get audited; `X-9r-Real-Ip`-style vendor-branded headers do not. Grep the app source for header reads feeding an authn/authz/limiter decision (`getHeader('x-...ip')`, `req.headers[...]` near `isLocal`/`getClientIp`/`limiter`), then test whether the edge layer that *should* sanitize the header is actually in the request path for the deployment mode you're looking at. "Trusted header produced by wrapper X" is only a control if wrapper X is always deployed — self-hosted apps commonly have a direct-to-framework path that skips it.
2. **Rate-limit identity is an authorization decision.** A limiter keyed on a spoofable field is a lockout bypass, full stop. Negative-control protocol from this pair: fixed spoofed value → does the limiter ever trip? rotating spoofed value → does it reset? The rotation differential *is* the proof. This generalizes across every product family on this wiki that keys lockouts on forwarded IPs (the Airflow/Sync-in/MISP lockout-drift pages all test counter *state advance*; here also test *identity stability*).
3. **Same guard, third bug class.** August's findings keyed locality on `Host`; September's key it on a custom IP header. Once you find one header-trusted locality decision in `dashboardGuard.js`, treat every field that guard consumes as a candidate — one confirmed spoofable input in a security decision is a confession about the module, not a single bug.

Replayable validation stays lab-only: a direct-to-Next.js 9router lab instance, `X-9r-Real-Ip: 127.0.0.1` canary request to `/api/v1/models` (positive) vs same request without the header (401 negative control), and lockout-bucket rotation with your own synthetic credentials; never against shared instances (rotating-header guessing locks nothing but still hammers real login endpoints).

## Sources

- [GitHub Advisory Database: 9router GHSA-86m2-fcxq-5q7c / CVE-2026-55641](https://github.com/advisories/GHSA-86m2-fcxq-5q7c)
- [GitHub Advisory Database: 9router GHSA-8gmq-j984-vp4r / CVE-2026-55638](https://github.com/advisories/GHSA-8gmq-j984-vp4r)
- Related (already patched): [GHSA-fhh6-4qxv-rpqj](https://github.com/advisories/GHSA-fhh6-4qxv-rpqj) MCP-plugin RCE, [GHSA-xrrh-p7f2-27vm](https://github.com/advisories/GHSA-xrrh-p7f2-27vm) legacy authz bypass
- September 22 fold: [GHSA-5mj8-gf6m-fhw8 / CVE-2026-56681](https://github.com/advisories/GHSA-5mj8-gf6m-fhw8), [GHSA-32gc-64m7-hj7v / CVE-2026-56682](https://github.com/advisories/GHSA-32gc-64m7-hj7v)
