# SAML, MCP, metadata, and render-boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-21.

This batch is durable because each item gives operators a reusable validation pattern: signed SAML assertion attribute injection, unauthenticated local MCP-to-PowerShell control, metadata-service credential disclosure through a low-privilege workflow, and sanitizer raw-text bypass that turns stored content into executable markup.

## What changed

- **samlify signed-assertion attribute injection** — [GHSA-34r5-q4jw-r36m](https://github.com/advisories/GHSA-34r5-q4jw-r36m) / CVE-2026-46490: vulnerable `samlify <2.13.0` escaped template substitutions only in XML attribute contexts. Values inserted into element text, including `<saml:AttributeValue>`, could inject closing/opening XML and add attacker-chosen `<saml:Attribute>` entries before the IdP signed the response. If an SP trusts SAML attributes for role/group authorization, a normal user-controlled profile field can become a privilege-escalation primitive.
- **Windows-MCP unauthenticated HTTP transport to PowerShell** — [GHSA-vrxg-gm77-7q5g](https://github.com/advisories/GHSA-vrxg-gm77-7q5g): vulnerable `windows-mcp <0.7.5` documented SSE and Streamable HTTP modes without authentication while installing wildcard CORS. The exposed MCP server includes a `PowerShell` tool that executes caller-controlled commands as the Windows user running the service. Default stdio mode is not affected; the offensive surface is HTTP-reachable MCP control planes.
- **OpenMetadata TEST_CONNECTION credential disclosure** — [GHSA-9vmh-whc4-7phg](https://github.com/advisories/GHSA-9vmh-whc4-7phg) / CVE-2026-46481: vulnerable `org.open-metadata:openmetadata-service <1.12.4` could return cleartext database credentials and the ingestion-bot JWT in the HTTP 201 response from `POST /api/v1/automations/workflows` for a low-privilege `TEST_CONNECTION` workflow. The leaked bot token can be replayed as `Authorization: Bearer <jwt>` against sensitive service APIs.
- **sanitize-html / Apostrophe `xmp` raw-text XSS** — [GHSA-rpr9-rxv7-x643](https://github.com/advisories/GHSA-rpr9-rxv7-x643) / CVE-2026-44990: vulnerable `sanitize-html =2.17.3` treated disallowed `<xmp>` content as raw text and appended it unescaped under the default discard path. Stored content wrapped in `<xmp>` can emerge from sanitization as live `<script>`, event-handler markup, or SVG script when rendered by applications that trust sanitized output.

## Operator triage

1. Search dependency inventories for `samlify <2.13.0`, `windows-mcp <0.7.5`, `org.open-metadata:openmetadata-service <1.12.4`, and `sanitize-html 2.17.3`.
2. For SAML targets, identify IdPs built on `samlify` and SPs that map signed attributes such as `role`, `groups`, `isAdmin`, `tenant`, or entitlement claims into authorization decisions.
3. During local-agent or developer-workstation reviews, enumerate exposed MCP listeners (`/mcp`, SSE, Streamable HTTP) and confirm whether a browser or remote host can reach the control plane without a bearer token, mTLS, origin validation, or loopback binding.
4. For OpenMetadata, test only with authorized low-privilege accounts. Capture whether `TEST_CONNECTION` responses echo masked secrets as cleartext or return bot tokens that can read database service objects with `include=all`.
5. For CMS/render surfaces, feed a benign `<xmp>` wrapped marker through the same sanitizer pipeline used for stored user content and verify whether the output reactivates disallowed markup.

## Replayable validation boundaries

- **SAML attribute-confusion test:** place an XML-breaking marker in an IdP-controlled user profile field that lands in `<saml:AttributeValue>`. Expected safe result: the value is XML-escaped or rejected before signing. Vulnerable result: the signed assertion contains an additional attacker-chosen attribute.
- **Authorization mapping test:** after confirming injection in a lab tenant, attempt to inject only harmless role/group names first. Escalation evidence should show the SP consumes injected attributes, not merely that the assertion XML changed.
- **MCP HTTP reachability test:** from an untrusted browser origin and a plain HTTP client, attempt MCP initialization against the advertised SSE/Streamable HTTP endpoint. Expected safe result: authentication, host/origin rejection, or no listener. Vulnerable result: unauthenticated tool listing or `PowerShell` tool invocation is accepted.
- **Metadata credential echo test:** send a low-privilege `TEST_CONNECTION` workflow request and inspect the 201 JSON response for database passwords or `openMetadataServerConnection.securityConfig.jwtToken`. Expected safe result: secrets are absent/redacted and bot tokens are never returned to the caller.
- **Raw-text sanitizer bypass test:** submit `<xmp><img src=x onerror=alert(1)></xmp>` or an inert callback variant in a disposable lab page. Expected safe result: dropped or escaped content. Vulnerable result: sanitizer output contains active HTML rather than inert text.

## Reporting heuristics

- Show the trust-boundary crossing, not just package presence: signed attribute injection accepted by an SP, unauthenticated MCP control-plane access, credential/token material returned to a regular user, or sanitized output becoming executable markup.
- Keep PoCs scoped to benign markers and lab tenants. For MCP and OpenMetadata, avoid running destructive shell/database actions; tool listing, harmless environment reads, or redacted token proof is usually enough.
- In SAML reports, include the IdP library/version, the exact profile field or claim source, the signed assertion diff, and the SP authorization decision that changed.
- In MCP reports, include bind address, transport mode, CORS/origin behavior, auth posture, reachable tool names, and the Windows user context for any harmless command proof.
- In sanitizer reports, include the sanitizer version, input payload, sanitized output, render sink, and whether the bug is stored, reflected, or admin-only.

## Notes on skipped items from this scan

- The androidqf and MVT path-traversal advisories are useful for forensic-tool hardening but do not add durable pentest/red-team operator guidance for the public Skillz surface.
- The Klever-Go read-only execution side-effect advisory is interesting for blockchain VM reviews, but it is too ecosystem-specific for a standalone Skillz page until a broader smart-contract VM boundary pattern emerges.
