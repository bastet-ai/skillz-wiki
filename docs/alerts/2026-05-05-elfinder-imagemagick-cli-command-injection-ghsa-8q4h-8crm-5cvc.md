# elFinder ImageMagick CLI command injection + URL-upload DNS-rebinding SSRF bypass

Source: GitHub Security Advisory [GHSA-8q4h-8crm-5cvc](https://github.com/advisories/GHSA-8q4h-8crm-5cvc) / CVE-2026-41247, updated 2026-05-06; [GHSA-8x3q-jpjh-qh5c](https://github.com/advisories/GHSA-8x3q-jpjh-qh5c) / CVE-2026-81889, updated 2026-08-31.

This is durable because file-manager image operations often look like harmless media metadata handling while still crossing into shell-backed processing. Any user-controlled image option that reaches a CLI command line is an execution boundary.

## Advisory summary

- **Product/package:** `studio-42/elfinder` / elFinder.
- **Impact:** command injection in the `resize` command when the ImageMagick CLI backend is used.
- **Trigger:** attacker-controlled `bg` / background-color parameter reaches resize or rotate processing and is interpolated into shell command construction.
- **Affected versions:** before 2.1.67.
- **Patched version:** 2.1.67.
- **Severity:** high; GitHub reports CVSS 3.1 score 9.8.

## Operator triage

1. Upgrade elFinder to **2.1.67 or later**.
2. If immediate upgrade is blocked, disable the `resize` command or avoid the ImageMagick CLI backend until fixed.
3. Restrict file-manager access to trusted users only; do not expose image-processing actions anonymously or broadly to low-privilege accounts.
4. Search web logs for `resize` requests containing unusual `bg` values, shell metacharacters, command separators, substitutions, encoded payloads, or unexpected color formats.
5. Check web-server process logs, ImageMagick temporary directories, and child-process telemetry for unexpected command execution around image resize activity.
6. Treat successful exploitation as code execution as the web-server user: preserve evidence, rotate secrets accessible to that user, and rebuild compromised hosts from clean images.

## Durable controls

- Prefer library APIs or argv-array process execution over shell string construction for media tools.
- Validate media options against strict grammar allowlists before they reach any backend. For colors, accept only explicitly supported forms such as named colors or bounded hex/RGB forms.
- Escape is a backup, not the boundary. The primary boundary is rejecting values that are not valid for the intended semantic field.
- Run image processing in a sandboxed worker with low privileges, no cloud metadata access, tight filesystem scope, and CPU/memory/time limits.
- Log normalized image-operation parameters and backend selection so suspicious transformations can be hunted after disclosure.

## August 31 follow-up: URL-upload SSRF protection bypass via DNS rebinding (GHSA-8x3q-jpjh-qh5c / CVE-2026-81889)

elFinder's remote URL upload path validates the target host by resolving it to an IP and rejecting private/loopback ranges. When PHP's cURL extension is unavailable, the connector falls back to `fsock_get_contents()`, which **re-resolves the original hostname** for the actual connection. The validation step and the fetch step use two different DNS lookups, so an attacker-controlled low-TTL or rotating A record passes the first check as a public IP and connects to a loopback/private IP on the second. The advisory classifies this as CWE-918 (SSRF) via a DNS-rebinding/TOCTOU primitive.

- **Affected versions:** up to `2.1.69` (confirmed on commit `8f2c3ffafcdd52cf4515f1eec172f4eee44552ad` and the `master` branch inspected 2026-07-24); the earliest affected version was not determined.
- **Patched version:** `2.1.70`.
- **Severity:** high (CWE-918 SSRF).
- **Preconditions:** PHP without the cURL extension, access to the URL-upload feature, permission to upload the MIME type the target returns, reachability from the PHP process to the internal target, and DNS behavior compatible with low/zero-TTL responses.

### Operator triage

1. Upgrade elFinder to **2.1.70 or later**.
2. Where the URL-upload feature is enabled, confirm whether the PHP runtime has the cURL extension: the bypass only reaches the `fsock_get_contents()` fallback when cURL is absent.
3. Treat any elFinder URL-upload feature as an SSRF surface, not just a file-upload feature.

### Replayable validation (lab / owned DNS only)

Preconditions: an authorized lab elFinder instance running an affected build with cURL disabled, an owned DNS zone or rebinding host under tester control, and a lab listener on loopback/RFC1918. No production targets, no cloud metadata, no internal service probing.

1. **Reproduce the two-lookup differential in the lab.** Point the upload URL at a tester-controlled hostname whose first resolution returns a public IP and whose second resolution returns the lab loopback address (low or zero TTL). Capture the validation response and the saved file.
2. **Positive proof is a file readback, not a service probe.** The advisory's demonstrated impact is that the internal service response is saved as an uploaded file and readable through elFinder. Prove it with the lab listener returning an inert canary string; confirm the canary appears in the uploaded file. Do not point the second resolution at cloud metadata, internal admin consoles, or real private services.
3. **Negative control.** Repeat the same hostname against elFinder `2.1.70` and against a runtime with cURL available; record that the connection no longer follows the re-resolved IP.
4. **Evidence to capture:** the affected elFinder version/commit, the cURL-absent runtime, the two DNS resolution results (public then private), the saved uploaded file with the inert canary, and the patched/cURL-present negative control.

### Durable lesson

- **Validation and fetch must resolve once and pin the address.** Any server-side fetch that checks a hostname against a private-range denylist and then opens a *second* connection to the same hostname is a DNS-rebinding/TOCTOU candidate. The check and the connect must share one resolved address.
- **The cURL-vs-`fsock` fallback split multiplies the surface.** Frameworks that have a hardened default path (cURL with resolver pinning or explicit `CURLOPT` behavior) and a weaker fallback (`fsockopen`/`fsock_get_contents`) frequently lose the SSRF guarantee on the fallback. Audit which runtime configuration a target actually uses, the patched behavior may only apply on one code path.
- **Pair with the [DNS rebinding local-service testing methodology](../methodology/dns-rebinding-local-service-testing.md):** this advisory is the same "the lookup is coming from inside the house" pattern, but it lands on a *server-side* fetch path (PHP connector), not a browser-origin one, and the readback is through the file manager's own download route.

## Sources

- [GitHub Advisory Database: elFinder GHSA-8q4h-8crm-5cvc / CVE-2026-41247](https://github.com/advisories/GHSA-8q4h-8crm-5cvc)
- [GitHub Advisory Database: elFinder GHSA-8x3q-jpjh-qh5c / CVE-2026-81889](https://github.com/advisories/GHSA-8x3q-jpjh-qh5c)
