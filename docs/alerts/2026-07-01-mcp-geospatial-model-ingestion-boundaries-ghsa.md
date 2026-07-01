# MCP SSRF, geospatial search, and model-ingestion boundary checks

Source: hourly offensive-security scan, 2026-07-01. Primary entries: GitHub Advisory Database [GHSA-pvrj-8cg3-j5f8](https://github.com/advisories/GHSA-pvrj-8cg3-j5f8) / CVE-2026-49857, [GHSA-c5r6-m4mr-8q5j](https://github.com/advisories/GHSA-c5r6-m4mr-8q5j) / CVE-2026-49856, [GHSA-582q-v28r-7cxr](https://github.com/advisories/GHSA-582q-v28r-7cxr) / CVE-2026-46487, [GHSA-2v4m-fw6c-g78f](https://github.com/advisories/GHSA-2v4m-fw6c-g78f) / CVE-2026-39379, [GHSA-wphc-7cm7-8mf7](https://github.com/advisories/GHSA-wphc-7cm7-8mf7) / CVE-2026-49014, and [GHSA-29pf-2h5f-8g72](https://github.com/advisories/GHSA-29pf-2h5f-8g72) / CVE-2026-4372.

These advisories are durable for operators because they expose repeatable boundary tests across modern attack surfaces: MCP tools that normalize URLs or skip local-network authorization, geospatial portals that proxy search and render AngularJS error pages, and data/AI ingestion paths that treat uploaded files or model configuration as trusted code-bearing input.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-pvrj-8cg3-j5f8](https://github.com/advisories/GHSA-pvrj-8cg3-j5f8) / CVE-2026-49857 | `auth-fetch-mcp` `auth_fetch` / `download_media` | IPv4-mapped IPv6 loopback addresses such as `::ffff:127.0.0.1` are normalized by Node's WHATWG URL parser to hex form (`::ffff:7f00:1`), bypassing a guard that only re-checks dotted IPv4 suffixes | Agent/MCP SSRF reviews need parser-normalization test cases, not just raw denylist literals. |
| [GHSA-c5r6-m4mr-8q5j](https://github.com/advisories/GHSA-c5r6-m4mr-8q5j) / CVE-2026-49856 | `@jshookmcp/jshook` network domain | raw HTTP/TCP/TLS latency tools used the central SSRF authorization guard, but ICMP probe and traceroute resolved targets and invoked native probes directly | MCP tool suites should prove every transport sink uses the same private-network authorization policy. |
| [GHSA-582q-v28r-7cxr](https://github.com/advisories/GHSA-582q-v28r-7cxr) / CVE-2026-46487 | GeoNetwork Elasticsearch-backed search API | request shapes that omit the expected query field can skip GeoNetwork ACL/filter injection before the request reaches Elasticsearch | Search-proxy assessments should test missing, empty, and alternate body shapes for authorization-filter fail-open behavior. |
| [GHSA-2v4m-fw6c-g78f](https://github.com/advisories/GHSA-2v4m-fw6c-g78f) / CVE-2026-39379 | GeoNetwork AngularJS error page | route/error text reflected from a crafted service URL can be interpreted as a client-side template expression | Legacy AngularJS portals need URL-to-error-page CSTI checks with harmless DOM canaries and authenticated-context boundaries. |
| [GHSA-wphc-7cm7-8mf7](https://github.com/advisories/GHSA-wphc-7cm7-8mf7) / CVE-2026-49014 | GDAL netCDF driver `scanForGeometryContainers` | oversized netCDF geometry attributes reached a fixed-size stack buffer | Geospatial upload/conversion services should include file-format metadata fields in parser harnesses, not only feature geometry payloads. |
| [GHSA-29pf-2h5f-8g72](https://github.com/advisories/GHSA-29pf-2h5f-8g72) / CVE-2026-4372 | Hugging Face `transformers` model loader | a model `config.json` internal attention implementation field could route loading to attacker-controlled Hub code despite `trust_remote_code` expectations | AI supply-chain reviews should treat model configuration fields as execution-routing inputs and verify owned-repo canaries with pinned fixed versions. |

Adjacent Open Babel duplicate and parser-crash updates were processed as covered by the [June 30 model parser/deserialization/identity boundary page](2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md). Pure availability-only parser/resource updates were processed without separate promotion.

## Replayable validation boundaries

### MCP URL and network-sink SSRF harness

- Preconditions: owned MCP server instances, isolated network namespace or lab host, an internal canary HTTP service bound to loopback/private IP, and no production tokens, memories, browser profiles, or operator credentials loaded into the MCP session.
- For URL-fetch tools, send paired requests through the same MCP tool call path:
  - denied controls: `http://127.0.0.1:<port>/canary`, `http://localhost:<port>/canary`, and a private RFC1918 literal;
  - parser-normalization probes: `http://[::ffff:127.0.0.1]:<port>/canary` and equivalent private IPv4-mapped IPv6 forms.
- Positive evidence is a denylist bypass where direct loopback/private literals are rejected but the IPv4-mapped IPv6 form reaches the canary service or returns canary content/path metadata.
- For network diagnostic tools, compare every sink exposed by the MCP server: HTTP/TCP/TLS RTT, ICMP probe, traceroute, DNS lookup, and download helpers. Positive evidence is one sink reaching a private canary while another sink correctly invokes the SSRF authorization guard.
- Keep evidence inert: route hit counters, response headers, fake tokens, and local callback logs only. Do not scan internal networks, read localhost admin panels, load real browser sessions, or exfiltrate files through download helpers.
- Negative controls: patched packages, a canonicalization routine that converts IPv4-mapped IPv6 back to an IP object before policy checks, and one shared authorization wrapper used by every outbound network primitive.

### GeoNetwork search ACL and CSTI checks

- Preconditions: owned GeoNetwork lab with at least one public record, one group-restricted record, one draft/non-public record, disposable users/groups, and a non-sensitive marker in each record title/abstract.
- Build a search-body matrix for the Elasticsearch-backed API: normal query, omitted `query`, empty object, alternate top-level keys, unexpected arrays, and malformed-but-accepted JSON bodies.
- Positive evidence for the ACL issue is a request shape that returns the restricted marker unauthenticated or as a user outside the record's group while the normal query path hides it.
- For the AngularJS client-side-template issue, use only harmless expressions/DOM markers in a crafted service URL that lands on the error page; capture whether the marker is evaluated or rendered as inert text.
- Do not enumerate real metadata, collect credentials, exploit administrator sessions, or use persistent JavaScript payloads. Keep CSTI proof to local lab users and DOM-marker screenshots or sanitized HTML snippets.
- Negative controls: fixed GeoNetwork releases, route-level tests that assert ACL filters are injected for every accepted request body shape, and an error page that context-encodes reflected route text before AngularJS processing.

### Geospatial and AI ingestion harness

- Preconditions: disposable conversion/inference workers, synthetic netCDF files, owned Hugging Face-compatible repositories, inert model code that writes only a marker in a temp directory, and no production datasets, notebooks, cloud credentials, or model weights.
- For GDAL, generate netCDF files with geometry-related attributes of increasing size and route them through the exact service path under test: upload preview, metadata extraction, tile generation, notebook helper, or batch conversion job.
- Positive GDAL evidence is limited to sanitizer output, process crash classification, stack trace/function name, accepted-file decision table, and fixed-version negative control. Do not pursue exploit reliability or production worker crashes.
- For `transformers`, create paired model configs: one benign baseline and one with the internal attention implementation field pointing at an owned canary repository. Load them through the same `from_pretrained()` wrapper the product uses.
- Positive AI evidence is an inert canary import/execution marker from the unexpected repository while `trust_remote_code` was expected to prevent remote code loading.
- Negative controls: GDAL 3.13.1 or later, file parsing in a sandboxed worker, explicit netCDF metadata size limits, `transformers` 5.3.0 or later, repository allowlists, revision pins, offline mode where appropriate, and CI tests that reject execution-routing config fields.

## Reporting notes

- Lead with the exact boundary crossed: **URL canonicalization to loopback SSRF**, **MCP diagnostic sink to private-network probe**, **search request shape to missing ACL filter**, **route reflection to AngularJS template execution**, **geospatial metadata to native parser**, or **model config to remote code loader**.
- Include affected and fixed versions, the minimal canary input shape, the expected denial or inert render, the observed result, and a patched-version negative control.
- Keep proof scoped and reversible: owned callback services, fake records, harmless DOM markers, sanitizer traces, temp-file markers, and disposable model repositories only.
