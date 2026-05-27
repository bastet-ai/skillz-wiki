# Hapi, Pimcore, tmp, and LiquidJS boundary batch (GHSA, 2026-05-26)

**Signal:** GitHub Advisory Database published a small follow-on batch after the prior template/container/CMS batch. The durable operator value is in four reusable validation patterns: duplicate-parameter parser differentials, authenticated CMS SQL query builders, temporary-file directory containment, redirect credential forwarding, and template partial sandbox option drift.

Promoted items:

- `GHSA-36hh-x5p5-jgc8` / `CVE-2026-44974`: `@hapi/content` duplicate parameter handling can enable upload-filter bypasses when another component resolves duplicates differently.
- `GHSA-h4ph-crvj-9h92` / `CVE-2026-44741`: Pimcore Admin Classic Bundle translation-grid date filter SQL injection through the filter `property` field.
- `GHSA-3234-gxc3-pq6f` / `CVE-2026-44739`: Pimcore custom reports column configuration SQL injection with error-message feedback.
- `GHSA-ph9p-34f9-6g65` / `CVE-2026-44705`: `tmp` path traversal through user-influenced `prefix`, `postfix`, or `dir` options causing file creation outside the intended temporary directory.
- `GHSA-vhjm-w67q-g75c` / `CVE-2026-44979`: `@hapi/wreck` forwards `Proxy-Authorization` across cross-host redirects when redirect following is enabled.
- `GHSA-9x9p-qf8f-mvjg` / `CVE-2026-44646`: LiquidJS `{% render %}` child contexts can drop a per-render `ownPropertyOnly: true` override and expose prototype-chain properties inside partials.

Use these as authorized validation patterns. Prefer harmless marker files, controlled callbacks, and lab accounts; do not exfiltrate production secrets or write outside an agreed disposable path.

## Operator checklist

### 1. Duplicate-parameter parser differentials in uploads

Where to look:

- Node/Hapi services using `@hapi/content < 6.0.2` in multipart, content-disposition, or content-type parsing paths.
- Upload flows where a WAF, proxy, edge function, storage layer, antivirus step, or application parser may disagree on whether the first or last duplicate parameter wins.
- File allowlists/denylists keyed from `filename`, extension, `boundary`, or `charset` parameters.

Safe proof shape:

1. Confirm the vulnerable parser version or embedded equivalent.
2. Send a non-executable upload with duplicate parameters, for example a benign text payload whose first `filename` is allowlisted and whose second `filename` has a marker extension.
3. Compare what each layer logs, stores, scans, and returns to the user.
4. Stop at proving parser disagreement; do not upload active web shells or bypass malware scanning in production.

Reporting heuristic: frame as **parameter smuggling across parser boundaries**. Strong reports include raw request bytes, each component's interpreted filename/content type, and the security decision that used the wrong interpretation.

### 2. Authenticated CMS admin SQLi in query-builder surfaces

Where to look:

- Pimcore admin panels exposing translation grids or custom reports.
- Accounts with translation view permissions or `reports_config`-style permissions.
- Admin JSON/filter/config endpoints that accept field names, SQL snippets, `where` clauses, or column configuration objects.

Safe proof shape:

1. Confirm affected Pimcore components and versions before testing.
2. Use an authorized low-privilege or scoped admin account, not a stolen session.
3. For the translation-grid issue, test whether a date filter `property` value is interpolated into SQL instead of allowlisted as a column name.
4. For custom reports, test with benign `SELECT` expressions or error-based markers that return database metadata, not user password hashes.
5. Capture the exact permission boundary: anonymous, authenticated admin, translation-only user, reports-config user, or super-admin.

Reporting heuristic: report **field-name/configuration input reaches SQL identifier/expression context**. The most useful evidence shows the vulnerable endpoint, the minimal permission required, the generated SQL/error response, and why keyword stripping or comment removal is bypassable.

### 3. Temporary-file APIs as filesystem boundary crossings

Where to look:

- Node applications using `tmp` with user-influenced `prefix`, `postfix`, `dir`, or equivalent wrapper options.
- Export/download, image-conversion, archive-building, report-generation, upload-staging, and plugin-build features that create temporary files from attacker-provided names.
- Services running with write access to application directories, shared volumes, web roots, job workspaces, or agent tool directories.

Safe proof shape:

1. Confirm `tmp` is vulnerable and identify the application parameter that flows into `prefix`, `postfix`, or `dir`.
2. Use traversal payloads only against a tester-controlled temporary base directory or an explicitly approved disposable target.
3. Prove containment failure with a harmless marker filename and file content.
4. Record whether the application later renames, serves, executes, or cleans up the escaped file.
5. Do not overwrite existing files. If overwrite behavior is relevant, demonstrate it in a local lab clone.

Reporting heuristic: frame as **temporary filename decoration becoming path control**. Good reports distinguish simple arbitrary file creation from stronger chains such as web-root write, config overwrite, package/plugin planting, or CI workspace poisoning.

### 4. Redirect-following credential leaks from HTTP clients

Where to look:

- Node services using `@hapi/wreck < 18.1.1` with `redirects` set to a positive value.
- Fetcher/proxy/import features where users can influence an initial URL and the service supplies proxy credentials or other sensitive headers.
- SSRF-like URL importers, webhook testers, URL previewers, package fetchers, and internal integration clients.

Safe proof shape:

1. Confirm redirect following is enabled; the default no-redirect behavior is not affected.
2. In a controlled environment, point the client at a tester-owned endpoint that redirects to a second tester-owned hostname.
3. Verify whether `Proxy-Authorization` is forwarded to the redirected hostname.
4. Use a dummy credential value created for the test. Never attempt to capture real proxy credentials in customer environments.

Reporting heuristic: report **sensitive header retention across origin changes**. Include the redirect chain, hostnames, client options, and the exact header that crossed the trust boundary.

### 5. Template partials dropping per-render sandbox options

Where to look:

- LiquidJS deployments that render untrusted templates with `parseAndRender(..., { ownPropertyOnly: true })` while the Liquid instance itself has `ownPropertyOnly: false`.
- Multi-tenant CMS themes, email/template previews, storefront snippets, docs generators, and plugin systems that allow `{% render %}` partials.
- Applications relying on own-property isolation to hide prototype-chain values or host object methods.

Safe proof shape:

1. Confirm vulnerable LiquidJS behavior and that untrusted templates can invoke `{% render %}`.
2. Create a lab partial that reads a benign inherited property from a provided object.
3. Show the property is hidden in the parent render but exposed inside the rendered partial.
4. Avoid reading real secrets from object prototypes or host application objects.

Reporting heuristic: frame as **render-time policy not propagated to child template context**. Strong reports include the engine instance options, per-render options, minimal template/partial pair, and the data boundary crossed.

## Non-signal this hour

Reviewed but not promoted as standalone guidance:

- `GHSA-8xx9-69p8-7jp3` / `CVE-2026-44645`: LiquidJS `renderLimit` DoS guard bypass through empty loop bodies. Useful for resilience testing, but weaker fit than the boundary-crossing LiquidJS partial issue.
- CISA KEV remained catalog `2026.05.26` with `CVE-2026-48172` already reflected in prior Skillz Wiki LiteSpeed cPanel guidance.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, and Disclosed did not add a new promotable offensive-operator delta during this pass.

## Sources

- [`@hapi/content` duplicate-parameter upload-filter bypass (`GHSA-36hh-x5p5-jgc8`)](https://github.com/advisories/GHSA-36hh-x5p5-jgc8)
- [Pimcore translation-grid date filter SQL injection (`GHSA-h4ph-crvj-9h92`)](https://github.com/advisories/GHSA-h4ph-crvj-9h92)
- [Pimcore custom reports column-configuration SQL injection (`GHSA-3234-gxc3-pq6f`)](https://github.com/advisories/GHSA-3234-gxc3-pq6f)
- [`tmp` path traversal through temporary-file options (`GHSA-ph9p-34f9-6g65`)](https://github.com/advisories/GHSA-ph9p-34f9-6g65)
- [`@hapi/wreck` `Proxy-Authorization` redirect leak (`GHSA-vhjm-w67q-g75c`)](https://github.com/advisories/GHSA-vhjm-w67q-g75c)
- [LiquidJS `{% render %}` `ownPropertyOnly` bypass (`GHSA-9x9p-qf8f-mvjg`)](https://github.com/advisories/GHSA-9x9p-qf8f-mvjg)
