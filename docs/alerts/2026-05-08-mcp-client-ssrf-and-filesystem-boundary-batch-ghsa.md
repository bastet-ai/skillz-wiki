# MCP client SSRF, filesystem, and spend-boundary batch

**Signal:** The same **2026-05-08 17:15 UTC** GitHub advisory batch included multiple MCP/client tools where unauthenticated or under-scoped helper surfaces became file reads, SSRF, telemetry leaks, or third-party API spend at operator expense.

## Advisories covered

- **n8n-mcp path traversal, redirect-following SSRF, and telemetry payload exposure** — [GHSA-8g7g-hmwm-6rv2](https://github.com/advisories/GHSA-8g7g-hmwm-6rv2): `n8n-mcp < 2.50.1`; patch to `2.50.1+`.
- **n8n-mcp authenticated SSRF through webhook/API client paths** — [GHSA-cmrh-wvq6-wm9r](https://github.com/advisories/GHSA-cmrh-wvq6-wm9r): `n8n-mcp >= 2.18.7, < 2.50.2`; patch to `2.50.2+`.
- **@puchunjie/doc-tools-mcp path traversal** — [GHSA-gcmm-c94j-j47x](https://github.com/advisories/GHSA-gcmm-c94j-j47x): `@puchunjie/doc-tools-mcp <= 1.0.18`; no fixed version listed at advisory time.
- **gmaps-mcp unauthenticated HTTP transport spend abuse** — [GHSA-52cq-7v8r-62c6](https://github.com/advisories/GHSA-52cq-7v8r-62c6): `gmaps-mcp <= 0.1.2`; patch to `0.1.3+`.
- **BerriAI LiteLLM SQL injection added to CISA KEV** — CVE-2026-42208: CISA added LiteLLM SQL injection to KEV on 2026-05-08 with a 2026-05-11 due date; treat exposed proxy databases and managed credentials as at risk.

## Why this is durable

MCP and agent helper tools compress many powers into one local service: read files, call internal URLs, forward credentials, invoke paid APIs, and persist workflow telemetry. The durable lesson is to protect **tool capability**, not just HTTP reachability. Authentication, path roots, redirect handling, egress policy, and spend budgets must be enforced at the tool boundary before model- or user-controlled strings become IO.

## Immediate triage

1. Inventory MCP servers reachable over HTTP or local networks, especially `n8n-mcp`, `doc-tools-mcp`, and `gmaps-mcp`.
2. Patch `n8n-mcp` to `2.50.2+` and `gmaps-mcp` to `0.1.3+`; disable or isolate `doc-tools-mcp <= 1.0.18` until a fixed release is verified.
3. Hunt for requests containing `..`, encoded path traversal, symlink targets, `file://`, localhost/private IPs, cloud metadata IPs, redirects to internal hosts, and telemetry payloads containing secrets or workflow data.
4. For LiteLLM, prioritize KEV triage: patch/mitigate per vendor guidance, rotate managed provider/API credentials, inspect proxy database reads/writes, and review prompt/proxy logs for SQL metacharacter probes.
5. For Google Maps or other paid API helpers, check unusual request volume, unauthenticated clients, new source IPs, and quota spikes.

## Durable controls

- Require authentication and explicit per-tool authorization even on localhost transports; bind sessions to caller identity, origin, and intended tool set.
- Resolve file arguments to canonical paths under an allowlisted root; reject symlinks, archives that escape roots, and post-check path mutations.
- Apply SSRF policy after redirects and DNS resolution; block loopback, link-local, RFC1918, cloud metadata, and internal service ranges by default.
- Redact and minimize telemetry before export; never include raw prompts, tool arguments, bearer tokens, or connector responses unless explicitly approved.
- Add per-tool rate limits, quota ceilings, and billing alerts so unauthenticated or compromised helper endpoints cannot silently burn third-party spend.
