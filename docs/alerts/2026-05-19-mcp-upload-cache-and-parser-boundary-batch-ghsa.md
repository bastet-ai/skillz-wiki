# MCP fetch, upload, cache, and parser-boundary batch

Source: GitHub Security Advisories, updated 2026-05-19:
[GHSA-jwp7-wg77-3w9v](https://github.com/advisories/GHSA-jwp7-wg77-3w9v),
[GHSA-82rc-gxrg-v4gf](https://github.com/advisories/GHSA-82rc-gxrg-v4gf),
[GHSA-6vp2-6r7m-2jvx](https://github.com/advisories/GHSA-6vp2-6r7m-2jvx),
[GHSA-w4qq-74h6-58wq](https://github.com/advisories/GHSA-w4qq-74h6-58wq), and
[GHSA-jggg-4jg4-v7c6](https://github.com/advisories/GHSA-jggg-4jg4-v7c6).

This batch is durable because the failures rhyme across agent tools, low-code platforms, media helpers, and schema loaders: a string that looked bounded at one layer was trusted later as a hostname, executable content type, cached privilege, filesystem path, or recursive object graph.

## What changed

- **Apify MCP server** fixed `@apify/actors-mcp-server < 0.9.21`, where `fetch-apify-docs` used `String.startsWith()` to allow documentation URLs. Prefix matches such as `https://docs.apify.com.evil.com/` could pass the allowlist, fetch attacker-controlled content, and return it to the LLM as markdown.
- **Budibase** fixed `budibase < 3.38.2`, where authenticated builders or table writers could upload active content such as SVG, HTML, JavaScript, or PHP through attachment routes. Object storage preserved browser-executable MIME types, turning attachments into persistent stored-XSS delivery points for app users.
- **Budibase backend-core** fixed `@budibase/backend-core < 3.38.2`, where public API role unassignment updated CouchDB but did not invalidate Redis user-cache entries. Revoked admin, builder, or app-level privileges could remain effective for the cache TTL, up to one hour.
- **AVideo** disclosed an unauthenticated image-read traversal in `view/img/image404Raw.php` through the `image` parameter. `getimagesize()` limited output to image-like files, but did not constrain the path, so private photos, thumbnails, poster frames, or sibling-app image files reachable by the PHP user could be read.
- **protobufjs** fixed descriptor-loading DoS in `protobufjs <= 7.5.7` and `>= 8.0.0, < 8.2.0`. Deeply nested JSON descriptors processed by `Root.fromJSON()` / `Namespace.addJSON()` could exhaust the JavaScript call stack.

## Operator triage

1. **Patch the exact trust-boundary packages.** Upgrade Apify MCP server to `0.9.21`, Budibase/Budibase backend-core to `3.38.2`, and protobufjs to `7.5.8` or `8.2.0`. Track AVideo for an upstream patch; until then, restrict or remove direct access to `view/img/image404Raw.php` if internet-facing.
2. **Treat MCP fetch allowlists as confused-deputy controls.** If an LLM sees fetched content, the hostname check is part of prompt-injection defense. Replace prefix checks with parsed URL hostname comparisons, punycode normalization, single canonicalization, and exact-origin matching.
3. **Assume attachment URLs execute unless isolated.** For Budibase-like apps, serve user uploads from a cookieless/static domain, force `Content-Disposition: attachment` for active types, block scriptable MIME types at upload, and regression-test SVG/HTML/JS under every upload route, not only public routes.
4. **Shorten privilege revocation windows.** After role changes, invalidate user/session caches by user ID and tenant, force reauthorization on the next request, and monitor for role-sensitive actions by recently revoked users inside the old TTL window.
5. **Do not use magic-byte checks as filesystem boundaries.** `getimagesize()` can prove a file is image-like; it cannot prove the path belongs under the intended image root. Use `realpath()`/prefix containment after rejecting `..`, null bytes, wrappers, and absolute paths.
6. **Budget descriptor and parser depth.** Any service that accepts protobuf JSON descriptors, schemas, policy documents, or nested metadata from users should enforce size and depth limits before recursive expansion and isolate schema loading where restart is safe.

## Replayable validation boundaries

- **URL allowlist boundary:** test `trusted.example.evil.com`, `trusted.example@evil.com`, alternate ports, trailing dots, mixed case, punycode, redirects, and DNS rebinding. Authorize the parsed hostname, not the raw string.
- **Upload render boundary:** upload SVG with inline script, HTML with JavaScript, and extension/MIME mismatches through every role-accessible route. Confirm storage metadata, response headers, content origin, cookies, and CSP prevent script execution in an authenticated app origin.
- **Cache invalidation boundary:** revoke each role through every API path, then immediately retry privileged endpoints with an existing session. The expected result is denial without waiting for TTL expiry.
- **Filesystem containment boundary:** request image helpers with `../`, URL-encoded traversal, absolute paths, wrapper schemes, empty parameters using request-URI fallbacks, and symlinked files. Only files under the intended root should resolve after canonicalization.
- **Parser resource boundary:** load nested JSON descriptors at increasing depth and size. Fail closed before stack exhaustion, high CPU, or unbounded allocation; record the rejected depth in tests.

## Durable controls

- Centralize URL, path, upload, cache, and parser-boundary checks so bypasses cannot hide in one-off route handlers.
- Treat every agent/MCP tool that fetches remote content as both SSRF and prompt-injection surface, even when its documented purpose sounds narrow.
- Separate stored user content from authenticated application origins; MIME filtering alone is not enough.
- Couple authorization mutations with cache/session invalidation in the same code path and add tests for API, UI, and bulk-update variants.
- Put recursion, allocation, and schema-loading budgets at the trust boundary before helper libraries expand attacker-shaped structures.
