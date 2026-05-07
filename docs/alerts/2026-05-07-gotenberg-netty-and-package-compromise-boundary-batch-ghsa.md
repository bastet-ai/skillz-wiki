# Gotenberg, Netty, and package-compromise boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where document-conversion services, network protocol codecs, and package trust roots crossed durable security boundaries.

## Advisories covered

- **Gotenberg unauthenticated conversion-service boundary issues** — [GHSA-4vmc-gm8v-m35h](https://github.com/advisories/GHSA-4vmc-gm8v-m35h), [GHSA-r33j-c622-r6qp](https://github.com/advisories/GHSA-r33j-c622-r6qp), [GHSA-3cv5-q585-h563](https://github.com/advisories/GHSA-3cv5-q585-h563), [GHSA-2pmr-289p-44r3](https://github.com/advisories/GHSA-2pmr-289p-44r3), [GHSA-rm4c-xj6x-49mw](https://github.com/advisories/GHSA-rm4c-xj6x-49mw), [GHSA-7v3r-m9c8-r855](https://github.com/advisories/GHSA-7v3r-m9c8-r855), [GHSA-rqgh-gxv4-6657](https://github.com/advisories/GHSA-rqgh-gxv4-6657): SSRF, DNS rebinding, webhook goroutine reuse DoS, arbitrary PDF read, ExifTool blocklist bypass, and metadata-key command execution show that document conversion remains a file/network/command boundary, not a harmless formatting helper.
- **PyTorch Lightning package compromise** — [GHSA-w37p-236h-pfx3](https://github.com/advisories/GHSA-w37p-236h-pfx3): compromised PyPI package versions require malware-style response, clean rebuilds, dependency pin review, and secret rotation for environments that installed or built from affected releases.
- **Netty parser and allocation boundary issues** — [GHSA-f6hv-jmp6-3vwv](https://github.com/advisories/GHSA-f6hv-jmp6-3vwv), [GHSA-rgrr-p7gp-5xj7](https://github.com/advisories/GHSA-rgrr-p7gp-5xj7), [GHSA-38f8-5428-x5cv](https://github.com/advisories/GHSA-38f8-5428-x5cv), [GHSA-57rv-r2g8-2cj3](https://github.com/advisories/GHSA-57rv-r2g8-2cj3), [GHSA-mj4r-2hfc-f8p6](https://github.com/advisories/GHSA-mj4r-2hfc-f8p6), [GHSA-2c5c-chwr-9hqw](https://github.com/advisories/GHSA-2c5c-chwr-9hqw), [GHSA-xxqh-mfjm-7mv9](https://github.com/advisories/GHSA-xxqh-mfjm-7mv9), [GHSA-jfg9-48mv-9qgx](https://github.com/advisories/GHSA-jfg9-48mv-9qgx): decompression bombs, CRLF injection, malformed transfer-encoding request smuggling, response desynchronization, LZ4/QPACK allocation exhaustion, MQTT 5 Properties parsing before message-size enforcement, and TE+CL coexistence bypasses reinforce the need for one canonical protocol parser result and explicit resource budgets.

## Why this is durable

The common failure is treating powerful infrastructure as plumbing. A document converter can fetch URLs, read files, and launch media tooling; a protocol codec can reinterpret request boundaries; a package install can execute attacker-controlled code during builds or runtime. Those surfaces need explicit trust contracts, not implicit convenience defaults.

## Immediate triage

1. Patch Gotenberg and remove public/tenant-direct access to conversion endpoints until SSRF, webhook, ExifTool, and PDF-expression fixes are deployed.
2. For affected Gotenberg fleets, hunt for internal URL fetches, webhook callbacks to private ranges, metadata keys containing ExifTool option syntax, and unexpected PDF reads or temp-file access.
3. Treat PyTorch Lightning affected-version installs as potential host compromise: preserve evidence, rebuild from known-good images, rotate tokens from a trusted system, and audit CI/package caches.
4. Patch Netty across edge services, API gateways, Java backends, MQTT brokers/bridges, and embedded clients; prioritize internet-facing proxy pairs, services that decompress request bodies, and MQTT 5 listeners using `netty-codec-mqtt` before **4.1.133.Final** or **4.2.13.Final**.
5. Add regression tests for TE+CL ambiguity, malformed transfer encodings, CRLF in Redis/proxy codecs, decompression byte budgets, QPACK/LZ4 allocation caps, MQTT Properties byte budgets/replay behavior, and HTTP client response desync.

## Durable controls

- Isolate conversion workers with deny-by-default egress, read-only roots, throwaway temp volumes, and no ambient credentials.
- Replace URL regex deny-lists with canonical parse, DNS resolution, redirect revalidation, and post-resolution IP allow/deny decisions.
- Treat media-tool metadata as command-adjacent input: validate both keys and values, block option syntax after canonicalization, and avoid stdin argument protocols where possible.
- Keep a single normalized protocol object for routing, auth, logging, and backend forwarding; never let adjacent layers parse raw bytes independently for security decisions, and enforce size limits before buffering extension/property sections.
- Build package-compromise playbooks around cache invalidation, provenance verification, SBOM diffing, and secret rotation—not only version upgrades.
