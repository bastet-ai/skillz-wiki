# django CMS page-cache Vary poisoning and plugin-tree cyclic-reparenting DoS

Source: GitHub Security Advisories REST `published` feed, 2026-08-24: [GHSA-fwjf-m4qw-9f2x](https://github.com/advisories/GHSA-fwjf-m4qw-9f2x) / [CVE-2026-54625](https://nvd.nist.gov/vuln/detail/CVE-2026-54625) and [GHSA-8jj7-4v57-frf5](https://github.com/advisories/GHSA-8jj7-4v57-frf5) / [CVE-2026-54623](https://nvd.nist.gov/vuln/detail/CVE-2026-54623). Fixed in `django-cms` `5.0.8` ([commit](https://github.com/django-cms/django-cms/commit/8758714b865ffa79c6bcd0e5c503958ea48885aa), [5.0.8 release](https://github.com/django-cms/django-cms/releases/tag/5.0.8)).

This batch is durable because it captures two reusable CMS testing patterns: a **cache-key / `Vary`-header differential** where the CMS emits a `Vary` response header but does not fold the varied request header into its own cache key (poisonable shared cache), and a **recursive-CTE traversal without a cycle guard** that an authenticated low-priv user can weaponize into a worker-stalling DoS. Both are directly replayable on any django CMS 5.x deployment below 5.0.8 and generalize to any framework that separates "emit `Vary`" from "key the cache on the varied value".

## What changed

- **Page cache ignores plugin-declared `Vary` headers (CVE-2026-54625, medium).** `_page_cache_key` keys only on cache prefix, site, language, path, and timezone. `set_page_cache` collects a plugin's `get_vary_cache_on()` headers and calls `patch_vary_headers` (so the *response* `Vary` header is correct), but stores and retrieves the page under a header-agnostic key. `get_page_cache` therefore returns whichever variant was cached first.
  - **Information disclosure:** when a plugin varies output on a request header (e.g. `Country-Code`), the variant rendered for the first anonymous visitor is served to everyone until the entry expires.
  - **Cache poisoning:** an unauthenticated attacker can prime the anonymous page cache with content rendered from attacker-chosen header values, which is then served to subsequent visitors.
  - Applies only when `CMS_PAGE_CACHE` is enabled and at least one plugin implements `get_vary_cache_on()`.
- **`move_plugin` allows cyclic reparenting (CVE-2026-54623, high).** The admin `move_plugin` endpoint accepts a `plugin_parent` POST parameter and, for an in-placeholder move, sets the plugin's parent to the target with no cycle/ancestor check. Reparenting a plugin under its own descendant creates a cycle in the plugin tree; the `WITH RECURSIVE` descendant/ancestor CTEs (`_get_descendants_cte` / `_get_ancestors_cte`) have no cycle clause or depth limit, so they recurse indefinitely (PostgreSQL/SQLite) or error at the recursion limit (MySQL). Any subsequent render/copy/delete on that subtree hangs and consumes application workers.

## Operator triage

1. **Fingerprint django CMS:** look for `cms/` static assets, `django-cms` version markers, `/admin/cms/` routes, and the presence of `CMS_PAGE_CACHE`. Capture version evidence below `5.0.8`.
2. **Find plugin-declared `Vary`:** identify plugins (or custom plugins) that call `get_vary_cache_on()`. The poisoning vector only exists where a varied plugin is rendered on a cached, anonymously-served page.
3. **Locate the move endpoint:** the cyclic-reparenting DoS needs an authenticated staff user with plugin-change permission on at least one placeholder. Map who holds that permission.
4. **Check the CTE dialect:** PostgreSQL/SQLite recurse indefinitely; MySQL errors at the recursion limit. The effect (worker stall vs. loud error) differs, but the corrupted tree is the durable artifact.

## Replayable validation boundaries

### Cache-key / `Vary` differential check

- **Confirm the cache is live and a plugin varies:** send two requests to the same anonymous page differing only on the varied header (e.g. `Country-Code: US` vs `GB`) and record that the response carries the expected `Vary: Country-Code` but the body is the *first* cached variant for both.
- **Prove poisoning with a canary:** with an unauthenticated session, prime the anonymous page cache by requesting the page once with an attacker-chosen varied header value that renders a benign, distinguishable marker (a canary string the plugin echoes). Then request the same page with a different header value and confirm the attacker-primed variant is still served.
- **Stop at the canary:** do not attempt to exfiltrate real user data or inject script payloads into the cached page. The proof is the *cross-visitor variant reuse*, not an XSS.
- **Pair with the `Vary` header:** the report should show the response advertises `Vary` while the body is header-agnostic, that mismatch is the reusable signal for other frameworks.

### Cyclic-reparenting DoS check

- **Use a disposable placeholder in a lab:** with an authorized low-priv staff account that can change plugins, move a plugin under one of its own descendants via the `move_plugin` endpoint.
- **Prove the hang safely:** observe that a subsequent render/copy/delete on the affected subtree stalls (indefinite on Postgres/SQLite) or errors at the recursion limit (MySQL). Capture the recursive-CTE query and the worker-stall timing.
- **Bound the blast radius:** report which workers/requests are affected and that the tree is left in a corrupted state. Do not attempt to stall a production worker pool or affect real users.

## Reporting heuristics

- For the cache issue, frame it as a **cache-key / `Vary` differential**: the framework emits the correct `Vary` header but keys its own cache without the varied value, so the shared anonymous cache is poisonable. Include the cache key composition, the plugin, the varied header, and the canary cross-visitor proof.
- For the DoS, frame it as a **missing cycle guard on a recursive CTE** reachable through a user-controlled tree mutation. Include the `move_plugin` payload, the resulting `parent_id` cycle, the recursive-CTE query, and the DB dialect behavior.
- State the fixed version (`5.0.8`) and the exact affected range (`< 5.0.8`).
- Separate the two findings in the report: the cache issue is unauthenticated (poisoning/disclosure) while the cyclic-reparenting issue is authenticated (staff + plugin-change permission).

## Safety

- **Authorized, in-scope targets only.** django CMS sites are often production marketing/content platforms; cache poisoning can affect real visitors. Coordinate with the asset owner and prefer lab replay.
- **No production data exfiltration.** Use canary markers, not real user data or script injection, to prove the cache differential.
- **No production worker stall.** Prove the cyclic-reparenting DoS on a lab instance with a disposable placeholder; never stall a live worker pool.
- **No RCE assumption.** Neither finding reaches code execution. The cache issue is disclosure/poisoning; the DoS is availability. Do not extrapolate to RCE or SQLi.

## Reviewed but not promoted here

- No KEV entry and no active-exploitation status attached to either CVE at scan time.
- The django CMS `5.0.8` release bundles both fixes; this page documents the pre-fix operator pattern rather than the patch.
