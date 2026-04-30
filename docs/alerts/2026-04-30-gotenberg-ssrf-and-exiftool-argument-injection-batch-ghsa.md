# Gotenberg SSRF and ExifTool argument-injection batch (GHSA-5q7p-7jgv-ww56 / GHSA-5vh4-rgv7-p9g4 / GHSA-q7r4-hc83-hf2q)

**Signal:** GitHub Security Advisories published **2026-04-30**. Gotenberg fixed a cluster of unauthenticated issues in webhook/download URL filtering and PDF metadata writing.

## What it is
The batch includes three high-impact paths:

- `GHSA-5q7p-7jgv-ww56` / CVE-2026-40280: default webhook and `downloadFrom` private-IP deny-list regexes were case-sensitive (`^https?://`). Uppercase schemes like `HTTP://169.254.169.254/...` bypassed filtering while Go normalized the scheme before connecting.
- `GHSA-5vh4-rgv7-p9g4` / CVE-2026-39383: with default empty webhook allow/deny lists, attacker-supplied `Gotenberg-Webhook-Url` values were accepted, enabling blind SSRF / internal POST probing and potential side effects.
- `GHSA-q7r4-hc83-hf2q` / CVE-2026-40281: the PDF metadata endpoint validated ExifTool metadata keys but not values. Newlines in values injected extra ExifTool stdin arguments such as `-FileName`, `-Directory`, `-SymLink`, or `-HardLink`, allowing file moves, overwrites, or link creation inside the container.

Affected package: Go module `github.com/gotenberg/gotenberg/v8` through `8.30.1` for the critical issues; webhook SSRF affects `8.29.1` through `<8.31.0`. Fixed version: `8.31.0`.

References: <https://github.com/advisories/GHSA-5q7p-7jgv-ww56>, <https://github.com/advisories/GHSA-5vh4-rgv7-p9g4>, <https://github.com/advisories/GHSA-q7r4-hc83-hf2q>

## Triage
1. Find internet-exposed Gotenberg instances, especially default Docker images and document-conversion services reachable from tenants.
2. Check whether webhook headers, `downloadFrom`, or PDF metadata write endpoints are exposed to untrusted users.
3. Review container filesystems and logs for unexpected writes, symlinks, hardlinks, moved PDFs, or callbacks to internal/private addresses.

## Mitigation
- Upgrade Gotenberg to `8.31.0` or later.
- Set explicit webhook/download allow-lists; do not rely only on regex deny-lists for private ranges.
- Block egress from conversion containers to metadata, localhost, and internal control-plane networks.
- Run conversion containers with least privilege, read-only roots where possible, and isolated temp volumes.

## Detection ideas
- Search requests for uppercase `HTTP://` / `HTTPS://` in webhook or `downloadFrom` fields.
- Look for `Gotenberg-Webhook-Url` targeting private, link-local, or loopback addresses.
- Hunt metadata JSON values containing `
-FileName=`, `
-Directory=`, `
-SymLink=`, or `
-HardLink=`.

## Durable lesson
Deny-lists must normalize before matching, and argument streams must sanitize both keys and values. Document conversion services are often unauthenticated file and network primitives; isolate them as if compromise is expected.
