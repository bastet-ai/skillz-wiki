# Agent, build, SSRF, and tool-execution boundary batch

Source: GitHub Security Advisories updated 2026-05-13.

This batch is durable because AI/tooling, build, and archive workflows keep collapsing “configuration” into execution or network authority. Treat model inputs, per-crawl overrides, package indexes, OpenAPI templates, webhook targets, and helper CLIs as untrusted program input.

## Advisories covered

- **Flowise SSRF enforcement failure** — [GHSA-qqvm-66q4-vf5c](https://github.com/advisories/GHSA-qqvm-66q4-vf5c): direct `node-fetch`/`axios` usage bypassed SSRF protection. Fixed in `flowise`/`flowise-components 3.1.0`.
- **Spring AI vector-store SpEL injection** — [GHSA-fvh3-672c-7p6c](https://github.com/advisories/GHSA-fvh3-672c-7p6c): user-controlled filter-expression keys could trigger SpEL/code injection. Fixed in `1.0.5` and `1.1.4`.
- **ArchiveBox per-crawl config RCE** — [GHSA-3h23-7824-pj8r](https://github.com/advisories/GHSA-3h23-7824-pj8r): unvalidated AddView config overrides could reach command execution.
- **apko package and filesystem trust** — [GHSA-hcwr-pq9g-rq3m](https://github.com/advisories/GHSA-hcwr-pq9g-rq3m), [GHSA-qq3r-w4hj-gjp6](https://github.com/advisories/GHSA-qq3r-w4hj-gjp6), [GHSA-m7hm-vm4x-28jf](https://github.com/advisories/GHSA-m7hm-vm4x-28jf): APKINDEX checksum verification, symlink-following dirFS traversal, and JWKS key type panic. Fixed in `1.2.5`/`1.2.7` depending on issue.
- **OpenClaw exec allowlist heredoc expansion** — [GHSA-x3h8-jrgh-p8jx](https://github.com/advisories/GHSA-x3h8-jrgh-p8jx): allowlist analysis rejected shell expansion in unquoted heredocs. Fixed in `2026.4.22`.
- **pyp2spec code injection** — [GHSA-r35x-v8p8-xvhw](https://github.com/advisories/GHSA-r35x-v8p8-xvhw): package metadata/spec generation could inject code. Fixed in `0.14.1`.
- **quarkus-openapi-generator auth-header overmatch** — [GHSA-fr8f-rwjx-f32v](https://github.com/advisories/GHSA-fr8f-rwjx-f32v): broad path-parameter matching could send auth headers to unintended operations. Fixed in `2.16.0-lts` and `2.17.0`.
- **n8n-mcp SSRF and sensitive logging** — [GHSA-cmrh-wvq6-wm9r](https://github.com/advisories/GHSA-cmrh-wvq6-wm9r), [GHSA-wg4g-395p-mqv3](https://github.com/advisories/GHSA-wg4g-395p-mqv3), [GHSA-pfm2-2mhg-8wpx](https://github.com/advisories/GHSA-pfm2-2mhg-8wpx): authenticated SSRF and MCP argument/request logging. Fixed in `2.50.2`, `2.47.13`, and `2.47.11` respectively.
- **Ray Parquet Arrow extension deserialization RCE** — [GHSA-mw35-8rx3-xf9r](https://github.com/advisories/GHSA-mw35-8rx3-xf9r): untrusted Parquet extension metadata could execute through deserialization. Fixed in `2.55.0`.
- **Electerm link/CLI code execution** — [GHSA-mpm8-cx2p-626q](https://github.com/advisories/GHSA-mpm8-cx2p-626q): unsafe links/command line handling enabled code execution. Fixed in `3.8.8`.

## Operator triage

1. Patch internet-facing workflow builders, AI/vector search services, archive crawlers, and MCP/agent gateways first.
2. Review recent SSRF-block logs and egress telemetry for metadata IPs, loopback, Unix-socket proxies, and internal service names.
3. Search task/crawl/build logs for user-controlled configuration keys reaching command lines, templates, expression languages, package indexes, or deserializers.
4. Rotate secrets exposed in MCP tool-call logs, package build logs, or archive/crawler configuration captures.

## Durable controls

- Centralize SSRF enforcement in one wrapper and forbid raw HTTP clients in plugin/tool code unless they call the wrapper.
- Compile or parameterize expression languages; never concatenate user keys into SpEL, filters, SQL, templates, or command arguments.
- Treat generated specs and package metadata as attacker-controlled. Escape for the target language, then test with malicious fixtures.
- Build/image tools must verify both repository metadata and downloaded artifact checksums; filesystem readers must reject symlink escapes before open.
- Logs should redact tool arguments by schema, not by best-effort string matching after serialization.
