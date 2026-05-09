# Hono render, JWT, cache, and prototype-boundary batch

**Signal:** The **2026-05-09 01:15 UTC** scan added web-framework advisories where text-rendering, JWT claim validation, cache variation, and template object mutation crossed trust boundaries.

## Advisory cluster

- **Hono JSX SSR CSS declaration injection** — [GHSA-qp7p-654g-cw7p](https://github.com/advisories/GHSA-qp7p-654g-cw7p): `hono <4.12.18` failed to safely encode style-object values during JSX server-side rendering, allowing attacker-controlled style values to inject additional CSS declarations. Patch to **4.12.18+**.
- **Hono JWT NumericDate claim validation weakness** — [GHSA-hm8q-7f3q-5f36](https://github.com/advisories/GHSA-hm8q-7f3q-5f36): `hono <4.12.18` accepted improperly validated `exp`, `nbf`, or `iat` claim types in `verify()`. Patch to **4.12.18+** and reject non-integer NumericDate values before authorization decisions.
- **Hono cache middleware ignores authorization variation** — [GHSA-p77w-8qqv-26rm](https://github.com/advisories/GHSA-p77w-8qqv-26rm): `hono <4.12.18` cache middleware did not honor `Vary: Authorization` / `Vary: Cookie`, risking cross-user cache leakage. Patch to **4.12.18+**.
- **Velocity.js prototype pollution via `#set` path assignment** — [GHSA-j658-c2gf-x6pq](https://github.com/advisories/GHSA-j658-c2gf-x6pq): `velocityjs <=2.1.5` allowed path assignment into prototype-bearing keys; no patched version was listed at scan time.

## Why this matters

Framework helpers are security boundaries. A renderer that treats CSS values as inert text, a JWT verifier that accepts the wrong claim type, a cache that ignores identity-bearing headers, or a template setter that can write `__proto__` all turn convenience APIs into privilege-bleed paths.

## Triage

1. Patch Hono to **4.12.18+** anywhere JSX SSR, JWT verification, or cache middleware is enabled.
2. Search for SSR paths that pass user-controlled values into style objects; add tests for `;`, comment, URL, and escaped-newline injection in style values.
3. Add JWT tests that reject string, float, object, array, `NaN`, negative, and extremely large `exp` / `nbf` / `iat` values before claims reach authorization logic.
4. Disable caching on authenticated routes until the cache key includes the authenticated principal or the middleware honors `Authorization`, `Cookie`, and application-specific tenant/session headers.
5. Treat Velocity templates and data paths as untrusted code-adjacent input; block `__proto__`, `prototype`, `constructor`, and dotted/bracket forms that resolve to prototype objects.

## Durable controls

- Renderers must encode at the grammar boundary being emitted: HTML text, attributes, URLs, JavaScript, and CSS each need distinct encoders.
- Cache policy should default to private/no-store for authenticated responses unless an explicit identity-safe key is configured.
- JWT validation should enforce RFC data types before semantic checks; do not coerce claim values.
- Template path setters need a denylist plus positive path grammar, object creation with null prototypes, and regression tests for prototype pollution payloads.
