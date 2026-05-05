# pypdf parser resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced three pypdf resource-exhaustion advisories updated after the previous scan: **CVE-2026-41314 / GHSA-x284-j5p8-9c5p**, **CVE-2026-41313 / GHSA-4pxv-j86v-mhcw**, and **CVE-2026-41312 / GHSA-7gw9-cf7v-778f**.

## Advisory details

### `/FlateDecode` image dimensions can exhaust RAM

- **Package:** PyPI `pypdf`
- **Affected:** `< 6.10.2`
- **Fixed:** `6.10.2`
- **Severity:** Medium
- **Issue:** a crafted PDF can combine `/FlateDecode` with large image size values so that decoding or image access allocates excessive memory.
- **References:** <https://github.com/advisories/GHSA-x284-j5p8-9c5p>, <https://github.com/py-pdf/pypdf/security/advisories/GHSA-x284-j5p8-9c5p>

### Incremental-mode trailer `/Size` values can trigger long runtimes

- **Package:** PyPI `pypdf`
- **Affected:** `< 6.10.2`
- **Fixed:** `6.10.2`
- **Severity:** Medium
- **Issue:** a crafted PDF with a large trailer `/Size` value can force long runtimes when loaded in incremental mode.
- **References:** <https://github.com/advisories/GHSA-4pxv-j86v-mhcw>, <https://github.com/py-pdf/pypdf/security/advisories/GHSA-4pxv-j86v-mhcw>

### `/FlateDecode` predictor parameters can exhaust RAM

- **Package:** PyPI `pypdf`
- **Affected:** `< 6.10.2`
- **Fixed:** `6.10.2`
- **Severity:** Medium
- **Issue:** a crafted stream compressed with `/FlateDecode`, `/Predictor` not equal to `1`, and oversized predictor parameters can cause excessive memory use during decode.
- **References:** <https://github.com/advisories/GHSA-7gw9-cf7v-778f>, <https://github.com/py-pdf/pypdf/security/advisories/GHSA-7gw9-cf7v-778f>

## Why this is durable

PDF parsers sit at a risky boundary: compact metadata can request huge work before the caller has a chance to apply business-level checks. Image dimensions, predictor settings, object counts, trailer sizes, and incremental-update structures are all **attacker-controlled allocation and iteration hints**.

The reusable lesson is not only “upgrade pypdf.” It is: **document parsers need explicit resource budgets around every metadata-to-work conversion**.

## Immediate triage

1. **Patch pypdf to `6.10.2+`** in services, workers, CLIs, preview pipelines, and serverless functions that parse untrusted PDFs.
2. **Inventory PDF ingress paths:** uploads, email attachments, document previews, OCR jobs, e-discovery imports, malware sandboxes, queue consumers, and internal tools that process customer-supplied PDFs.
3. **Put parsing behind limits:** memory cgroups, CPU timeouts, max file size, max expanded stream size, max page/image dimensions, max object count, and worker-level kill/retry policies.
4. **Separate parsing from privileged contexts:** run PDF extraction in a low-privilege worker with no ambient cloud credentials or write access beyond a scratch directory.
5. **Treat parser hangs as security signals:** repeated timeouts, OOM kills, or queue poison-pill behavior should create security telemetry, not only operational alerts.

## Hunt ideas

- Search dependency locks for `pypdf<6.10.2`, especially in document-processing, ML-ingest, PDF preview, OCR, and ticketing/email ingestion services.
- Query logs for PDF jobs that terminate by timeout, OOM, container restart, or abnormal worker death after receiving user-controlled documents.
- Add regression fixtures with extreme `/Size`, `/FlateDecode` image dimensions, and predictor values to prove worker limits catch parser amplification.
- Verify that queue retry settings do not repeatedly process the same malicious PDF until the worker pool is exhausted.
- Confirm that uploaded files are quarantined or tagged after repeated parser resource failures.

## Durable controls

- Treat file-format metadata as untrusted code-adjacent input when it controls allocation, loop bounds, recursion, decompression, or object graph traversal.
- Enforce budgets both inside libraries where possible and outside libraries with process/container limits.
- Prefer fail-closed parser APIs that expose max dimensions, max decompressed bytes, and max object counts; wrap libraries that do not.
- Make parser workers disposable: small blast radius, short credentials, read-only inputs, write-only outputs, and no shared mutable state.
- Maintain corpus-based regression tests for malicious but syntactically valid documents, not only malformed samples.

## Operator lesson

Resource exhaustion bugs are boundary bugs. If a one-kilobyte metadata field can demand gigabytes of RAM or minutes of CPU, the parser has accepted attacker-controlled economics.
