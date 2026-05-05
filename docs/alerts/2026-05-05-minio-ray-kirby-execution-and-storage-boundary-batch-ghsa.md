# MinIO, Ray, and Kirby execution/storage boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced four durable advisories updated after the previous scan: **Ray CVE-2026-41486 / GHSA-mw35-8rx3-xf9r**, **MinIO CVE-2026-40344 / GHSA-9c4q-hq6p-c237**, **MinIO CVE-2026-41145 / GHSA-hv4r-mvr4-25vw**, and **Kirby CVE-2026-34587 / GHSA-jcjw-58rv-c452**.

## Advisory details

### Ray Data Parquet Arrow extension deserialization RCE

- **Package:** PyPI `ray`
- **Affected:** `>= 2.49.0, < 2.55.0`
- **Fixed:** `2.55.0`
- **Severity:** High
- **Issue:** Ray Data globally registers custom PyArrow extension types such as `ray.data.arrow_tensor`, `ray.data.arrow_tensor_v2`, and `ray.data.arrow_variable_shaped_tensor`. When PyArrow reads Parquet metadata containing those extension names, Ray's extension deserializer passes attacker-controlled metadata bytes to `cloudpickle.loads()`, enabling code execution during schema parsing before row data is read.
- **References:** <https://github.com/advisories/GHSA-mw35-8rx3-xf9r>, <https://github.com/ray-project/ray/security/advisories/GHSA-mw35-8rx3-xf9r>

### MinIO unsigned-trailer upload signature bypasses

- **Package:** Go `github.com/minio/minio`
- **Affected:** releases from `RELEASE.2023-05-18T00-05-36Z` through the final open-source `minio/minio` release noted in the advisory
- **Fixed:** MinIO AIStor `RELEASE.2026-04-11T03-20-12Z`
- **Severity:** High
- **Issues:**
  - `PutObjectExtractHandler` / Snowball auto-extract failed to verify signatures for `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, accepting a valid access key plus fabricated signature.
  - `PutObjectHandler` and `PutObjectPartHandler` could skip signature verification when credentials were supplied only through query-string `X-Amz-Credential`; the verification gate depended on the `Authorization` header while authorization used either source.
  - In both paths, an attacker who knows a valid access key with write permission can write arbitrary objects without knowing the secret key.
- **References:** <https://github.com/advisories/GHSA-9c4q-hq6p-c237>, <https://github.com/advisories/GHSA-hv4r-mvr4-25vw>

### Kirby dynamic option double-resolution SSTI

- **Package:** Composer `getkirby/cms`
- **Affected:** `< 4.9.0`; `>= 5.0.0, < 5.4.0`
- **Fixed:** `4.9.0`, `5.4.0`
- **Severity:** High
- **Issue:** Kirby option fields (`checkboxes`, `color`, `multiselect`, `select`, `radio`, `tags`, and `toggles`) that source options from a query or API could treat dynamic option values/text as templates a second time. If option data is influenced by an authenticated Panel user or by an untrusted API/data source, template expressions can be evaluated server-side, exposing protected data or altering content/behavior.
- **References:** <https://github.com/advisories/GHSA-jcjw-58rv-c452>, <https://github.com/getkirby/kirby/security/advisories/GHSA-jcjw-58rv-c452>

## Why this is durable

These advisories are different technologies, but the trust-boundary shape is the same:

- Ray let file metadata become deserialization bytecode.
- MinIO let credential metadata become identity without requiring matching cryptographic proof in every upload handler.
- Kirby let dynamic option data become a server-side template after an earlier trusted query phase.

The reusable bug class is **second-phase interpretation of untrusted metadata**. A value first appears to be schema, credential placement, or display text; later, another subsystem interprets it as executable code, authentication state, or server-side template syntax.

## Immediate triage

1. **Patch first:** Ray to `2.55.0+`; Kirby to `4.9.0+` or `5.4.0+`; MinIO deployments per the vendor's fixed AIStor release or migration guidance.
2. **Inventory ingestion paths:** Ray/PyArrow/Pandas Parquet reads from user, partner, data-lake, object-store, or pipeline-provided files; MinIO S3-compatible upload surfaces; Kirby Panel sites using dynamic option fields or `OptionsApi` / `OptionsQuery`.
3. **Assume object stores are data-integrity sensitive:** for exposed MinIO deployments, review object write logs around unsigned-trailer uploads, Snowball auto-extract requests, multipart uploads, query-string credentials, and unexpected object creation/overwrites.
4. **Treat Ray Data readers as code-execution surfaces:** quarantine untrusted Parquet files, run data ingestion in isolated workers, and avoid shared credentials in parser processes.
5. **Review Kirby dynamic options:** confirm all option values from queries/APIs are trusted, escaped as data, or no longer double-resolved after patching.

## Hunt ideas

- Search Python dependency locks and container images for `ray>=2.49,<2.55`; grep code for `ray.data.read_parquet`, `pyarrow.parquet.read_table`, and `pandas.read_parquet` in processes where Ray is imported.
- Inspect data-lake/object-store access logs for newly introduced Parquet files from untrusted principals immediately before worker crashes, unusual outbound connections, or unexpected child processes.
- In MinIO logs, look for `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, `X-Amz-Meta-Snowball-Auto-Extract: true`, `PutObjectPart`, query-string `X-Amz-Credential`, missing/odd `Authorization`, and writes using default or low-privilege access keys.
- Rotate MinIO keys that were broadly distributed, default, embedded in clients, or observed in suspicious upload paths; verify bucket policies after patching.
- Grep Kirby blueprints/plugins for dynamic options on `checkboxes`, `color`, `multiselect`, `select`, `radio`, `tags`, and `toggles`; test with literal `{{ ... }}` strings from untrusted sources and confirm they render as text, not executed queries.

## Durable controls

- Do not deserialize executable formats (`pickle`, `cloudpickle`, language object graphs) from file metadata, even when the file format is otherwise considered structured data.
- Keep signature verification and authorization coupled in a single fail-closed path. Every handler variant must prove the credential source, signature, and allowed action match.
- Avoid parser behavior that depends on header presence instead of the authenticated credential source actually used by policy decisions.
- Treat template syntax crossing a data boundary as tainted until explicitly escaped or wrapped in a typed literal.
- Add handler-parity tests: every upload/import/multipart/extract code path should share authentication invariants and regression tests.
- Run data and document ingestion workers with least privilege, no persistent secrets, network egress controls, and immutable input staging.

## Operator lesson

The dangerous moment is often not the first parse. It is the second interpreter that sees the same bytes later and decides they are code, credentials, or a template. Security reviews need to follow metadata through every phase until it becomes inert or intentionally authoritative.
