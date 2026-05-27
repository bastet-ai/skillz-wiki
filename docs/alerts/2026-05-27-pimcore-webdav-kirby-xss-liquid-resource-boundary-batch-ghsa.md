# Pimcore WebDAV, Kirby frontend XSS, and LiquidJS resource-boundary batch (GHSA, 2026-05-27)

**Signal:** GitHub Advisory Database published a second May 27 batch with reusable offensive-testing value: unauthenticated Pimcore WebDAV asset deletion through a missing auth/permission check, Kirby frontend stored XSS through URI-scheme sanitization drift, and LiquidJS filter-level resource-limit bypasses that are useful when DoS/resource testing is explicitly in scope.

Promoted items:

- `GHSA-wc7j-g8wx-m2qx` / `CVE-2026-45260`: Pimcore exposes `/asset/webdav{path}` without a WebDAV authentication plugin, and `Tree::move()` can delete a source asset before resolving the current user or enforcing asset permissions.
- `GHSA-qvjf-922g-pj44` / `CVE-2026-45368`: Kirby CMS frontend renderers for KirbyTags and image blocks can preserve script-executing link values such as `javascript://x%0A...`, enabling stored XSS where semi-trusted content authors or content-sync inputs are in scope.
- `GHSA-r7g9-xpmj-5fcq` / `CVE-2026-45617` and `GHSA-hh27-hf48-9f5q` / `CVE-2026-45357`: LiquidJS `strip_html` and `date` filters expose separate CPU/output amplification paths that bypass the practical protection expected from `memoryLimit` / `renderLimit` controls.

Use these only in authorized tests. For resource-exhaustion checks, get explicit approval, use small calibration payloads, and prefer local or staging environments. Do not delete production assets or execute XSS payloads against real users.

## Operator checklist

### 1. Pimcore WebDAV `MOVE` as an unauthenticated asset-deletion boundary

Where to look:

- Pimcore `<= 12.3.6` installations with the built-in WebDAV route enabled.
- Public or semi-public `/asset/webdav/` routes, especially when asset paths are guessable from frontend media URLs.
- Asset libraries with predictable sibling filenames in the same directory, because the unauthenticated deletion proof requires two existing asset paths.
- Prior Pimcore findings where an asset path disclosure, index listing, sitemap, or CDN URL corpus already identifies candidate source/destination assets.

Safe proof shape:

1. Confirm the affected Pimcore version from `composer.lock`, headers, release metadata, or an approved authenticated check.
2. Verify route exposure with a harmless WebDAV method such as `OPTIONS /asset/webdav/` and capture allowed methods. Do not mutate assets during discovery.
3. In a local clone or approved staging target, create two disposable assets in the same directory, for example `/products/source-test.txt` and `/products/existing-test.txt`.
4. Send a WebDAV `MOVE` request from the source path to the existing destination path and observe whether the source asset is deleted before the request errors on missing current-user context.
5. For production bug-bounty proof, stop at version + route + method exposure unless the program explicitly allows destructive validation. If mutation proof is required, use only pre-approved disposable assets created for the test.

Reporting heuristic: frame this as **missing WebDAV authentication plus move-path permission check drift**. Strong reports include the route exposure, vulnerable version, the two disposable asset paths, the request/response pair, and before/after evidence showing deletion or unauthorized overwrite.

### 2. Kirby CMS content-render XSS through link-scheme normalization gaps

Where to look:

- Kirby CMS `<= 4.9.0` or `>= 5.0.0 <= 5.4.0`.
- Sites where non-admin or semi-trusted users can update `textarea` or `blocks` fields through the Panel.
- Frontend forms, CMS importers, localization sync, Markdown/content-file pipelines, or other write paths that eventually render KirbyTags or blocks.
- Templates that render `(link: ...)`, `(image: ... link: ...)`, built-in `image` blocks with links, imported HTML blocks, or custom uses of `Html::a()` / `Html::link()` with untrusted input.

Safe proof shape:

1. Confirm an affected Kirby version and identify a field that renders into the site frontend.
2. Insert a harmless marker link first and verify the exact frontend template path where the link appears.
3. Test a non-executing URI-shape marker that demonstrates the normalization boundary, for example a controlled `javascript://x%0Aalert(1)`-style value in a lab or with a safe inert payload agreed by the program.
4. In production, avoid stealing cookies, invoking Panel APIs, or targeting real admin sessions. Prefer a benign `alert(document.domain)` equivalent only where the rules explicitly allow XSS proof.
5. Capture both stored content and rendered HTML, because the Panel itself may not execute the payload while the site frontend does.

Reporting heuristic: report **stored content authoring crosses into frontend script execution**. Include the author role required, field type, renderer path, stored value, rendered `<a href>` or image block output, and the realistic privilege escalation path such as frontend-origin access to same-origin Panel APIs.

### 3. LiquidJS filter resource-limit bypasses as scoped DoS validation

Where to look:

- Applications using `liquidjs < 10.26.0` for `strip_html` ReDoS checks.
- Applications using `liquidjs <= 10.25.7` where the `date` filter format is attacker-influenced, especially if the app relies on `memoryLimit` or `renderLimit` as safety controls.
- Template preview, email template, storefront theme, CMS personalization, and user-authored notification systems that render Liquid with user-controlled values or filter arguments.

Safe proof shape:

1. Confirm the LiquidJS version and map whether the attacker controls a filtered value, a date format argument, or both.
2. For `strip_html`, start with tiny unmatched opener sequences such as repeated `<script` in a local/staging render path and measure timing growth. Do not jump to large payloads on shared production systems.
3. For `date`, test whether a context-controlled format like `%5000d` produces output far larger than the configured `memoryLimit` or exceeds the expected `renderLimit`.
4. Keep payloads below agreed thresholds and capture relative scaling rather than causing outage. A valid report usually only needs proof that the configured guard does not apply.
5. Separate exploitability from impact: many programs treat DoS as special-scope. Make the report about **resource-limit bypass in a reachable template surface**, not generic availability theory.

Reporting heuristic: strong LiquidJS reports show the vulnerable package version, the exact template expression, which input is attacker-controlled, configured limits, measured output/timing at small payload sizes, and why the render path is reachable by an untrusted or low-privilege user.

## Non-signal this hour

Reviewed but not promoted as new standalone guidance:

- `GHSA-39vq-49qm-r2mc` / `CVE-2026-45334`: Kirby content-lock user ID/email disclosure is useful for account enumeration but lower-signal than the content-render XSS path for this wiki.
- PortSwigger Research stayed on the Top 10 web hacking techniques of 2025.
- Trail of Bits stayed on the already-covered zizmor GitHub Actions static-analysis hardening article.
- ProjectDiscovery stayed on already-covered Neo / Nuclei / DAST proof-loop material.
- GitHub Security Blog remained GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.
- CISA KEV remained catalog `2026.05.26` with `CVE-2026-48172` already reflected.

## Sources

- [Pimcore WebDAV missing authorization in `MOVE` handling (`GHSA-wc7j-g8wx-m2qx`)](https://github.com/advisories/GHSA-wc7j-g8wx-m2qx)
- [Kirby CMS frontend XSS from links in KirbyTags and image blocks (`GHSA-qvjf-922g-pj44`)](https://github.com/advisories/GHSA-qvjf-922g-pj44)
- [LiquidJS `strip_html` ReDoS via quadratic backtracking (`GHSA-r7g9-xpmj-5fcq`)](https://github.com/advisories/GHSA-r7g9-xpmj-5fcq)
- [LiquidJS `date` filter memory/render limit bypass (`GHSA-hh27-hf48-9f5q`)](https://github.com/advisories/GHSA-hh27-hf48-9f5q)
