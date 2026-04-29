# PhpSpreadsheet IOFactory SSRF/RCE and row-index DoS batch (GHSA-q4q6-r8wh-5cgh / GHSA-84wq-86v6-x5j6 / GHSA-7c6m-4442-2x6m)

**Signal:** GitHub Security Advisories published **2026-04-29**. PhpSpreadsheet disclosed a high-impact file-loading issue plus two row-index denial-of-service issues.

## What it is
Three related PhpSpreadsheet advisories landed together:

- `GHSA-q4q6-r8wh-5cgh` / `CVE-2026-34084`: `IOFactory::load()` can become SSRF or RCE when `$filename` is attacker-controlled because PHP stream wrappers and remote paths may be interpreted as load targets.
- `GHSA-84wq-86v6-x5j6` / `CVE-2026-40863`: SpreadsheetML XML reader can burn CPU on unbounded row indexes.
- `GHSA-7c6m-4442-2x6m` / `CVE-2026-40902`: XLSX row dimensions can trigger CPU denial of service with unbounded row numbers.

Affected package: Composer `phpoffice/phpspreadsheet`. The SSRF/RCE issue is fixed in `1.30.3`, `2.1.15`, `2.4.4`, `3.10.4`, and `5.6.0`; the row-index DoS fixes are one patch later in each supported line (`1.30.4`, `2.1.16`, `2.4.5`, `3.10.5`, `5.7.0`).

References:

- <https://github.com/advisories/GHSA-q4q6-r8wh-5cgh>
- <https://github.com/advisories/GHSA-84wq-86v6-x5j6>
- <https://github.com/advisories/GHSA-7c6m-4442-2x6m>

## Triage
1. Search for `IOFactory::load`, `Reader\`, uploaded spreadsheet imports, and spreadsheet preview/conversion jobs.
2. Prioritize flows where users can supply filenames, paths, URLs, or uploaded spreadsheet content.
3. Check whether import workers can reach metadata services, internal admin panels, cloud APIs, or local files.
4. Identify asynchronous queues where malicious files can exhaust CPU and starve other jobs.

## Mitigation
- Upgrade to the newest fixed patch line; prefer `5.7.0+` where migration allows.
- Treat user-supplied spreadsheet locations as untrusted input: resolve uploads to server-owned paths and reject URLs, wrapper schemes, UNC paths, and symlinks.
- Run spreadsheet parsing in a sandboxed worker with CPU, memory, wall-clock, file, and egress limits.
- Disable PHP URL wrappers for file-loading paths where possible.
- Add row-count, dimension, and compressed/uncompressed-size limits before full parse.

## Detection ideas
- Look for spreadsheet import requests containing `http://`, `https://`, `php://`, `phar://`, `file://`, `ftp://`, or unusually large row numbers/dimensions.
- Alert on parser workers making unexpected egress to metadata IPs, loopback, RFC1918 ranges, or application-internal hostnames.
- Correlate high CPU import jobs with recent uploaded spreadsheets and failed conversion attempts.

## Durable lesson
Spreadsheet parsers are archive extractors, XML parsers, renderers, and file fetchers at once. Put them behind the same sandbox and URL-policy controls used for document conversion services.
