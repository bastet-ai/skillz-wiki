# Django cache, upload, and session-boundary batch

**Signal:** The **2026-05-08 22:15 UTC** advisory scan added three Django request/response boundary issues where cache policy, upload framing, and session-cookie variation can quietly cross trust boundaries.

## Advisory cluster

- **`Vary: *` cache leakage** — [GHSA-5hrc-gvxj-w55p](https://github.com/advisories/GHSA-5hrc-gvxj-w55p): Django `UpdateCacheMiddleware` in `Django >=5.2,<5.2.14` and `>=6.0,<6.0.5` could cache responses whose `Vary` header contained `*`, risking private data being stored and served.
- **ASGI upload memory-limit bypass** — [GHSA-w26r-rmm8-9c29](https://github.com/advisories/GHSA-w26r-rmm8-9c29): missing or understated `Content-Length` values could bypass Django's `FILE_UPLOAD_MAX_MEMORY_SIZE` expectation and force large in-memory uploads in affected Django releases.
- **Session cookie cache variation gap** — [GHSA-7h2m-m8vj-598h](https://github.com/advisories/GHSA-7h2m-m8vj-598h): with `SESSION_SAVE_EVERY_REQUEST=True`, responses could fail to vary on cookies when the session was not otherwise modified, letting a cached public page expose another user's session.

## Why this matters

These are cache and framing bugs, not just framework patch notes. Shared caches must never guess whether a response is private, and application upload limits are not a substitute for byte limits at the reverse proxy or ASGI server.

## Triage

1. Patch Django to **5.2.14+** or **6.0.5+** where those trains are used; unsupported series were not fully evaluated, so treat older exposed deployments as suspect.
2. Audit sites using Django's site-cache middleware, CDN caching, or reverse-proxy caching for authenticated or session-adjacent pages.
3. Put upload byte limits at the edge (`client_max_body_size`, Envoy/HAProxy body limits, ASGI server limits), not only in Django settings.
4. Review `SESSION_SAVE_EVERY_REQUEST=True` deployments and any public pages that can touch session middleware while being cacheable.
5. Hunt cache logs for authenticated responses stored with `Vary: *`, absent `Vary: Cookie`, or unexpectedly large ASGI request bodies with missing/short `Content-Length`.

## Durable controls

- Treat `Vary: *`, cookies, authorization headers, and session middleware as hard cache-deny signals unless explicitly proven safe.
- Enforce request-size limits before request bodies reach framework parsers.
- Make cache keys include every identity-bearing dimension or do not cache the response.
- Add integration tests for shared-cache behavior around anonymous-to-authenticated transitions.
