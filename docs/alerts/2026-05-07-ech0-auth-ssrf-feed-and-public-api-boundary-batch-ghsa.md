# Ech0 auth, SSRF, feed, and public-API boundary batch

**Sources:** GHSA-fpw6-hrg5-q5x5, GHSA-p64j-f4x9-wq66, GHSA-8mc6-xjpr-h98x, GHSA-pj6q-4vq4-r8cg, GHSA-rgj7-vg8v-j4wr, GHSA-3v85-fqvh-7rxf, GHSA-rj4g-rqgh-rx9h

## Why this matters

A cluster of Ech0 advisories shows how small trust-boundary misses combine into account, network, privacy, and integrity exposure:

- Never-expiring access tokens have no `exp` claim; logout panics, repository revocation skips non-positive TTLs, and admin token deletion removes the DB row without blacklisting the JWT ID. Fixed in `github.com/lin-snow/Ech0` `1.4.8-0.20260503041146-eab62379c795`.
- OAuth redirect validation compares only scheme and host, ignoring path/query/fragment while preserving the caller-supplied redirect URI in signed state. Fixed in `1.4.8-0.20260503040728-a7e8b8e84bd1`.
- The Connect handler uses an unsafe HTTP requester for peer connect info, allowing authenticated SSRF to internal/cloud metadata URLs. Fixed in `1.4.8-0.20260503040602-091d26d2d942`.
- Public like endpoints allow unauthenticated repeated metric mutation and write amplification. Fixed across the May 3 patched snapshots.
- RSS/Atom feed rendering passes through raw HTML markdown and unescaped tag names, creating stored XSS in feed readers. Fixed in `1.4.8-0.20260503035519-fd320fe3e902`.
- Public comment APIs serialize commenter email addresses. Fixed in `1.4.8-0.20260503034700-cb8d7a997dd8`.

## Operator triage

1. Upgrade Ech0 deployments to a patched `1.4.8` snapshot or later; pin by commit if package metadata has not yet converged across `Ech0`/`ech0` module casing.
2. Rotate JWT signing keys if any never-expire access token may have leaked; DB deletion alone is not enough for affected versions.
3. Revoke and re-issue OAuth clients with exact redirect URI allowlists, including path and scheme, not just host.
4. Block Connect peer URLs to loopback, link-local, RFC1918, metadata, Unix-socket proxy, and DNS-rebinding targets at the HTTP client layer.
5. Audit public comment endpoints and exported feed content for PII exposure or attacker-supplied tags/raw HTML.
6. Rate-limit and authenticate state-mutating public endpoints; if anonymous engagement is required, bind actions to anti-abuse tokens and deduplicate per actor.

## Hunt prompts

- Access tokens created with "never expire" followed by failed logout attempts, panics, or successful API use after admin deletion.
- OAuth login flows where the `redirect_uri` host matches an allowlist but path points to analytics, redirector, CDN, user-content, or attacker-controlled pages.
- Connect URLs targeting `169.254.169.254`, `127.0.0.0/8`, `::1`, private address space, internal DNS names, or unusual high ports.
- Repeated unauthenticated `PUT /api/echo/like/:id` calls, fav-count spikes, or cache invalidation bursts.
- Feed items containing `<script>`, event handlers, SVG/MathML, raw HTML blocks, or tag names containing markup.
- Public `/api/comments` responses or logs containing guest email fields.

## Durable controls

- Token revocation must operate on token identity (`jti`) regardless of expiry shape; never let optional claims create exceptional revocation paths.
- OAuth redirect matching should be exact or use pre-registered, normalized URI templates with no caller-controlled path expansion.
- SSRF-safe HTTP clients should be the default for all user-influenced URLs, including health checks and federation/connect features.
- Public API serializers should use explicit response DTOs; never return persistence models with PII fields by default.
- Feeds are HTML surfaces: escape all interpolated fields and disable raw HTML unless a sanitizer with a feed-reader threat model is in place.
- Every state mutation needs authentication, authorization, rate limits, and replay/deduplication semantics appropriate to the asset being modified.
