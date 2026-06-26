# Proxy, scanner, and container path boundary checks

Source: hourly offensive-security scan, 2026-06-26. Primary entries: GitHub Advisory Database [GHSA-vgrc-hq28-p3xp](https://github.com/advisories/GHSA-vgrc-hq28-p3xp), [GHSA-cg7w-rg45-pc59](https://github.com/advisories/GHSA-cg7w-rg45-pc59) / CVE-2026-48782, [GHSA-5vwr-qchf-q4pf](https://github.com/advisories/GHSA-5vwr-qchf-q4pf), [GHSA-cr2j-534f-mf3g](https://github.com/advisories/GHSA-cr2j-534f-mf3g) / CVE-2026-48785, and [GHSA-4c8j-mgm4-qqvp](https://github.com/advisories/GHSA-4c8j-mgm4-qqvp) / CVE-2026-48788. Adjacent Hysteria crash advisory [GHSA-qh5x-rfwf-rvfv](https://github.com/advisories/GHSA-qh5x-rfwf-rvfv) was reviewed but is not promoted beyond grouping context because it is availability-only.

These items are durable for operators because they expose reusable trust boundaries: authenticated relay sessions caching a first UDP destination while later packets carry new destinations, AI URL downloaders relying on incomplete private-address canonicalization, SBOM scanners executing build-tool commands from repository-controlled paths, container runtime path allowlists using string-prefix matching, and same-origin image proxies accepting upstream `Content-Type` claims but serving sniffed HTML.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-vgrc-hq28-p3xp](https://github.com/advisories/GHSA-vgrc-hq28-p3xp) | Hysteria UDP relay | authenticated client opens a UDP session to an allowed first destination, then reuses the same session ID for packet-scoped destinations that ACL should reject | Test relay/proxy products for **session-scoped authorization over packet-scoped destinations**, especially localhost and private-network UDP egress. |
| [GHSA-cg7w-rg45-pc59](https://github.com/advisories/GHSA-cg7w-rg45-pc59) / CVE-2026-48782 | `pydantic-ai` / `pydantic-ai-slim` `FileUrl` downloads | `force_download='allow-local'` plus routable IPv6 transition forms could bypass metadata/private-IP blocking in NAT64 or ISATAP environments | Add IPv4-compatible, NAT64, local NAT64, and ISATAP encodings to SSRF canonicalization checks for AI/browser/file-fetch integrations. |
| [GHSA-5vwr-qchf-q4pf](https://github.com/advisories/GHSA-5vwr-qchf-q4pf) | `@cyclonedx/cdxgen` Maven scanning | repository-controlled Maven module paths reached command construction while some invocations used `shell: true` | Treat SBOM/scanner server endpoints as build executors; use disposable repos with inert metacharacter path canaries. |
| [GHSA-cr2j-534f-mf3g](https://github.com/advisories/GHSA-cr2j-534f-mf3g) / CVE-2026-48785 | Apptainer `limit container paths` | configured allowed container path such as `/data/safe` also matched sibling prefixes such as `/data/safe-but-unsafe` | Test container execution allowlists with sibling-prefix, trailing-slash, symlink, and canonical-path negative controls. |
| [GHSA-4c8j-mgm4-qqvp](https://github.com/advisories/GHSA-4c8j-mgm4-qqvp) / CVE-2026-48788 | Remark42 `/api/v1/img` image proxy | upstream `Content-Type: image/*` was trusted during fetch, but served bytes were sniffed and could become `text/html` on the target origin | Hunt image/avatar/media proxies where **admission MIME** and **served MIME** are decided by different signals. |

## Operator triage

1. **Pin the authorization unit.** If a relay authorizes a connection, stream, tunnel, or session once, verify whether each later packet/message can change the security-relevant destination.
2. **Canonicalize before allow/deny decisions.** URL fetchers should compare the routed endpoint after DNS, redirects, IP literal parsing, IPv6 transition decoding, and network-stack normalization.
3. **Treat scanners as code runners.** SBOM, SCA, container, and IaC scanners often invoke native build tools. A repository path, module name, workspace name, or config field can become a shell or argument boundary.
4. **Use sibling-prefix controls.** Path allowlists need exact directory containment after cleaning and symlink resolution; `/safe` must not authorize `/safe2` or `/safe-but-unsafe`.
5. **Compare MIME decisions end to end.** A proxy that checks upstream headers but later serves sniffed bytes can turn attacker-hosted content into same-origin HTML.

## Replayable validation boundaries

### UDP relay ACL session harness

- Preconditions: explicit authorization, disposable Hysteria or similar relay lab, one authenticated low-privilege client, and two UDP echo services under operator control.
- Configure ACLs so the first UDP destination is allowed and a second localhost or private-network canary destination is denied.
- Send a baseline packet to the allowed destination, then reuse the same relay session or tunnel identifier for the denied destination.
- Positive evidence is only canary echo reachability or server log routing to the denied canary. Do not probe real internal DNS, service discovery, telemetry, admin daemons, or production private networks.
- Capture product version, ACL excerpt, first destination, later destination, session identifier behavior, and fixed-version negative control.

### AI/file-fetch SSRF canonicalization harness

- Preconditions: owned application using `pydantic-ai` URL download features or a local harness, synthetic media/document URLs, and an owned callback service.
- Test only the application paths where untrusted input can influence `FileUrl`/`ImageUrl`/`AudioUrl`/`VideoUrl`/`DocumentUrl` and `allow-local`-style behavior is enabled.
- Build a decision table for plain IPv4, IPv4-mapped IPv6, IPv4-compatible IPv6, 6to4, well-known NAT64, local-use NAT64, operator-configured NAT64 prefixes, and ISATAP. Include whether the lab network actually routes each form.
- Use owned callback IPs/domains and synthetic metadata-shaped endpoints. Never request real cloud metadata, Kubernetes APIs, localhost admin panels, or internal production services.

### SBOM scanner repository-path command harness

- Preconditions: isolated scanner worker or `cdxgen` server lab, disposable Maven repository, no real credentials in the scanner environment, and a temp directory for marker output.
- Create paired Maven modules whose directory names differ only by harmless shell metacharacter canaries or newline/space variants.
- Submit the repository through the same path in scope: CLI scan, CI scan, or server-mode `POST /sbom` equivalent.
- Evidence should show child-process arguments, rejected metacharacters, or marker-only output in the temp directory. Do not run arbitrary commands, read environment variables, or scan attacker repos on production runners.

### Container execution path allowlist harness

- Preconditions: lab Apptainer host, non-production setuid configuration, temp container/image directories, and explicit authorization to run disposable containers.
- Configure a single allowed path such as `/tmp/skillz-safe` and create sibling controls such as `/tmp/skillz-safe2` and `/tmp/skillz-safe-but-unsafe`.
- Attempt to run only inert containers from each path and record allowed/denied decisions before and after path cleaning, symlink resolution, and patched-version comparison.
- Do not use this harness to bypass production HPC or multi-user container controls, mount sensitive host paths, or run privileged payloads.

### Same-origin media proxy MIME harness

- Preconditions: lab Remark42 or comparable image proxy, owned upstream server, harmless HTML marker body, and no production user sessions.
- Serve paired upstream responses: valid image bytes with `image/*`, HTML bytes mislabeled as `image/*`, and image bytes mislabeled as non-image.
- Request each through the proxy and capture admission decision, stored bytes, served `Content-Type`, `X-Content-Type-Options`, CSP/sandbox headers, and whether the browser treats the response as a document.
- Stop at harmless DOM markers. Do not steal cookies, perform admin actions, deliver links to real users, or persist malicious content in production caches.

## Reporting notes

- Lead with the exact crossed boundary: **UDP session ACL to later packet destination**, **URL canonicalization to routable private endpoint**, **repository path to shell/build-tool command**, **path-prefix allowlist to sibling container directory**, or **upstream MIME claim to same-origin HTML**.
- Include versions, configuration, path/URL normalization table, canary values, network routing assumptions, and fixed-version negative controls.
- Keep all proofs synthetic: owned callbacks, disposable Maven modules, temp container paths, lab relay credentials, harmless HTML markers, and marker-only command output.
