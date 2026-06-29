# TYPO3 extension indexer, crawler, and render-boundary checks

Source: hourly offensive-security scan, 2026-06-29. Primary entries: GitHub Advisory Database [GHSA-3h52-6v6j-6wwv](https://github.com/advisories/GHSA-3h52-6v6j-6wwv) / CVE-2026-8827, [GHSA-c72x-mc2p-wv7x](https://github.com/advisories/GHSA-c72x-mc2p-wv7x) / CVE-2026-46724, [GHSA-jr8m-x4p7-p3v5](https://github.com/advisories/GHSA-jr8m-x4p7-p3v5) / CVE-2026-8727, [GHSA-fq39-62gx-8hqx](https://github.com/advisories/GHSA-fq39-62gx-8hqx) / CVE-2026-46722, [GHSA-67j3-jmm3-32xc](https://github.com/advisories/GHSA-67j3-jmm3-32xc) / CVE-2026-46723, and [GHSA-8x3j-439w-537c](https://github.com/advisories/GHSA-8x3j-439w-537c) / CVE-2026-46725.

These advisories are useful for operators because they expose reusable TYPO3 extension boundaries: backend indexer configuration crossing into filesystem reads and internal table indexing, crawler-controlled response headers crossing into PHP object deserialization, frontend cookies crossing into persistent content-element state, and extension helper APIs crossing from custom code into SQL construction.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-c72x-mc2p-wv7x](https://github.com/advisories/GHSA-c72x-mc2p-wv7x) / CVE-2026-46724 | `tpwd/ke_search` file indexer | backend-configured indexer directories were not normalized before filesystem traversal | Test search-indexer configuration as a privileged file-read boundary, not only as content crawling. |
| [GHSA-fq39-62gx-8hqx](https://github.com/advisories/GHSA-fq39-62gx-8hqx) / CVE-2026-46722 | `tpwd/ke_search` OOXML parser | crafted indexed `xlsx`/`pptx` documents could resolve XML external entities and write fetched content into the search index | Treat document indexing as an XXE/SSRF/file-read sink with canary-only payloads. |
| [GHSA-67j3-jmm3-32xc](https://github.com/advisories/GHSA-67j3-jmm3-32xc) / CVE-2026-46723 | `tpwd/ke_search` page and content indexers | `additional_tables` accepted arbitrary table and field names, copying internal TYPO3 data into the public search index | Check whether low-tier backend editors can turn internal tables into indexed, searchable data. |
| [GHSA-jr8m-x4p7-p3v5](https://github.com/advisories/GHSA-jr8m-x4p7-p3v5) / CVE-2026-8727 | `tomasnorre/crawler` Site Crawler | crawler-fetched `X-T3Crawler-Meta` response headers were passed to PHP `unserialize()` | If admins can configure crawler targets, attacker-controlled lab endpoints become deserialization input sources. |
| [GHSA-8x3j-439w-537c](https://github.com/advisories/GHSA-8x3j-439w-537c) / CVE-2026-46725 | `mmc/ceselector` Content Element Selector | unauthenticated cookies were unserialized when the content element used static persistent mode | Frontend state mechanisms need deserialization review when plugin configuration toggles persistence. |
| [GHSA-3h52-6v6j-6wwv](https://github.com/advisories/GHSA-3h52-6v6j-6wwv) / CVE-2026-8827 | `friendsoftypo3/tt-address` helper repository | custom extension calls to `AddressRepository::getSqlQuery()` could pass untrusted input into SQL construction | Review custom TYPO3 glue code that wraps extension helper methods; default installation reachability is not enough. |

## Operator triage

1. **Inventory installed extensions and versions.** Capture TYPO3 core version plus `ke_search`, `crawler`, `ceselector`, and `tt_address` versions from Composer or Extension Manager before testing reachability.
2. **Map who can change extension configuration.** The indexer and crawler findings become stronger when non-admin backend roles can edit file indexers, table indexers, scheduler jobs, or crawler target URLs.
3. **Separate backend-privileged chains from unauthenticated frontend chains.** `ke_search` and `crawler` generally start from backend-controlled configuration; `ceselector` may expose a frontend cookie sink if the affected content element is present and static persistent mode is enabled.
4. **Prefer index evidence over secret reads.** For file/table/XXE findings, prove the boundary with synthetic canaries that appear in the search index, not with `/etc/passwd`, TYPO3 install secrets, or customer data.
5. **Custom code matters.** For `tt_address`, look for site-specific extensions that call helper methods with request parameters, route variables, search terms, filters, or imported address data.

## Replayable validation boundaries

### `ke_search` file, table, and OOXML indexer harness

- Preconditions: TYPO3 lab or customer-approved staging system, affected `ke_search` version, disposable backend role, synthetic filesystem marker, synthetic TYPO3 table/field, and a search index you are allowed to reset.
- For path traversal, configure only a disposable indexer directory that attempts to reach a marker file under a temporary lab path. Run the indexer and verify whether the marker appears in indexed output.
- For arbitrary table/field indexing, create a synthetic table or record with a unique canary value. Configure `additional_tables` or equivalent page/content indexer settings to include that marker, then query the search index for only the canary.
- For OOXML XXE, place a crafted `xlsx`/`pptx` canary document in an approved indexed directory. Use an owned callback URL or temporary local marker file and verify only callback receipt or synthetic marker indexing.
- Negative controls: fixed `ke_search` versions, normalized base-directory checks, role without indexer edit permission, and parser behavior with external entities disabled.
- Do not read TYPO3 config files, database credentials, private uploads, customer records, cloud metadata, or production internal services.

### Site Crawler header-to-unserialize harness

- Preconditions: affected `crawler` extension, crawler-enabled test page, scheduler or manual crawl path you are allowed to invoke, owned HTTP endpoint, and no production gadget-chain testing.
- Point a lab crawler configuration at an owned endpoint that returns a harmless `X-T3Crawler-Meta` canary shaped to prove parser reachability without invoking magic methods or loading gadgets.
- Trigger only the approved crawler job and capture request logs, response headers, TYPO3 error/log evidence, and fixed-version behavior.
- Stop at deserialization reachability or benign class/marker handling in a lab. Do not publish PHP object injection gadget chains, execute commands, or crawl unowned URLs.

### Content Element Selector cookie sink harness

- Preconditions: affected `ceselector` version, page containing the content element, `Persistent Mode: Static`, disposable frontend session, and harmless cookie canaries.
- Confirm the plugin setting first. Then send a cookie value that proves whether frontend-controlled state crosses into the unserialize path without invoking application gadgets.
- Evidence should include extension version, plugin setting, unauthenticated/authenticated state, cookie name/value shape redacted to a marker, and patched negative control.
- Do not use production visitor pages, persistent payloads, session hijacking, or object chains that execute code.

### `tt_address` custom helper SQL harness

- Preconditions: affected `tt_address` version, source access or approved black-box route tied to a custom extension, seeded address records with canary fields, and database query logging in a lab.
- Search custom code for `AddressRepository::getSqlQuery()` and trace whether request input reaches sorting, filtering, grouping, field names, or raw condition parameters.
- Exercise only a seeded canary route and show SQL-shape change or canary extraction that cannot happen through the intended filter grammar.
- Do not enumerate production address books, dump tables, bypass legal scope, or report `tt_address` as directly exploitable without a reachable custom call path.

## Reporting notes

- Lead with the concrete boundary: **backend indexer path to file read**, **OOXML entity to index/callback**, **table configuration to internal record exposure**, **crawler response header to PHP deserialization**, **frontend cookie to persistent element unserialize**, or **custom helper API to SQL construction**.
- Include extension version, TYPO3 role, plugin/indexer configuration, route or scheduler path, exact canary, and a fixed-version or permission-denied negative control.
- Keep artifacts synthetic: marker files, owned callback domains, lab records, harmless cookies, and redacted logs.
