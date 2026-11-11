# SAML, MCP, OpenMetadata, MVT, and render-boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-21. Refreshed from the 2026-06-10 hourly scan after GitHub's updated feed resurfaced samlify/OpenMetadata and the adjacent Mobile Verification Toolkit path-traversal advisory. Refreshed again on 2026-08-31 with an OpenMetadata FreeMarker email-template SSTI follow-up.

This batch is durable because each item gives operators a reusable validation pattern: signed SAML assertion attribute injection, unauthenticated local MCP-to-PowerShell control, metadata-service credential disclosure through a low-privilege workflow, hostile forensic bundles crossing analyst-workstation filesystem boundaries, and sanitizer raw-text bypass that turns stored content into executable markup.

## What changed

- **samlify signed-assertion attribute injection**, [GHSA-34r5-q4jw-r36m](https://github.com/advisories/GHSA-34r5-q4jw-r36m) / CVE-2026-46490: vulnerable `samlify <2.13.0` escaped template substitutions only in XML attribute contexts. Values inserted into element text, including `<saml:AttributeValue>`, could inject closing/opening XML and add attacker-chosen `<saml:Attribute>` entries before the IdP signed the response. If an SP trusts SAML attributes for role/group authorization, a normal user-controlled profile field can become a privilege-escalation primitive.
- **Windows-MCP unauthenticated HTTP transport to PowerShell**, [GHSA-vrxg-gm77-7q5g](https://github.com/advisories/GHSA-vrxg-gm77-7q5g): vulnerable `windows-mcp <0.7.5` documented SSE and Streamable HTTP modes without authentication while installing wildcard CORS. The exposed MCP server includes a `PowerShell` tool that executes caller-controlled commands as the Windows user running the service. Default stdio mode is not affected; the offensive surface is HTTP-reachable MCP control planes.
- **OpenMetadata TEST_CONNECTION credential disclosure**, [GHSA-9vmh-whc4-7phg](https://github.com/advisories/GHSA-9vmh-whc4-7phg) / CVE-2026-46481: vulnerable `org.open-metadata:openmetadata-service <1.12.4` could return cleartext database credentials and the ingestion-bot JWT in the HTTP 201 response from `POST /api/v1/automations/workflows` for a low-privilege `TEST_CONNECTION` workflow. The leaked bot token can be replayed as a bearer token against sensitive service APIs.
- **Mobile Verification Toolkit hostile-backup path traversal**, [GHSA-5h3g-px23-w6vw](https://github.com/advisories/GHSA-5h3g-px23-w6vw) / CVE-2026-46486: vulnerable `mvt <=2026.4.28` used the `fileID` value from an iOS backup `Manifest.db` directly in filesystem paths. Crafted backups can make `mvt-ios decrypt-backup` write outside the intended output directory or make `mvt-ios check-backup` open files outside the backup directory.
- **sanitize-html / Apostrophe `xmp` raw-text XSS**, [GHSA-rpr9-rxv7-x643](https://github.com/advisories/GHSA-rpr9-rxv7-x643) / CVE-2026-44990: vulnerable `sanitize-html =2.17.3` treated disallowed `<xmp>` content as raw text and appended it unescaped under the default discard path. Stored content wrapped in `<xmp>` can emerge from sanitization as live `<script>`, event-handler markup, or SVG script when rendered by applications that trust sanitized output.

## Operator triage

1. Search dependency inventories for `samlify <2.13.0`, `windows-mcp <0.7.5`, `org.open-metadata:openmetadata-service <1.12.4`, `mvt <=2026.4.28`, and `sanitize-html 2.17.3`.
2. For SAML targets, identify IdPs built on `samlify` and SPs that map signed attributes such as `role`, `groups`, `isAdmin`, `tenant`, or entitlement claims into authorization decisions.
3. During local-agent or developer-workstation reviews, enumerate exposed MCP listeners (`/mcp`, SSE, Streamable HTTP) and confirm whether a browser or remote host can reach the control plane without a bearer token, mTLS, origin validation, or loopback binding.
4. For OpenMetadata, test only with authorized low-privilege accounts. Capture whether `TEST_CONNECTION` responses echo masked secrets as cleartext or return bot tokens that can read database service objects with `include=all`.
5. For MVT, treat third-party iOS backups as hostile input. Prioritize labs, malware-analysis pipelines, help-desk evidence intake, and bug-bounty programs that run MVT against user-supplied backups.
6. For CMS/render surfaces, feed a benign `<xmp>` wrapped marker through the same sanitizer pipeline used for stored user content and verify whether the output reactivates disallowed markup.

## Replayable validation boundaries

- **SAML attribute-confusion test:** place an XML-breaking marker in an IdP-controlled user profile field that lands in `<saml:AttributeValue>`. Expected safe result: the value is XML-escaped or rejected before signing. Vulnerable result: the signed assertion contains an additional attacker-chosen attribute.
- **Authorization mapping test:** after confirming injection in a lab tenant, attempt to inject only harmless role/group names first. Escalation evidence should show the SP consumes injected attributes, not merely that the assertion XML changed.
- **MCP HTTP reachability test:** from an untrusted browser origin and a plain HTTP client, attempt MCP initialization against the advertised SSE/Streamable HTTP endpoint. Expected safe result: authentication, host/origin rejection, or no listener. Vulnerable result: unauthenticated tool listing or `PowerShell` tool invocation is accepted.
- **Metadata credential echo test:** send a low-privilege `TEST_CONNECTION` workflow request and inspect the 201 JSON response for database passwords or `openMetadataServerConnection.securityConfig.jwtToken`. Expected safe result: secrets are absent/redacted and bot tokens are never returned to the caller.
- **MVT hostile-backup workspace test:** in a disposable analyst VM, create a synthetic iOS backup with a crafted `Manifest.db` `fileID` that attempts to resolve outside the backup/output root. Expected safe result: traversal is rejected or constrained to the expected root. Vulnerable result: a canary-only read or write lands outside the intended workspace. Do not test against real analyst home directories, SSH keys, cloud tokens, case material, or production workstations.
- **Raw-text sanitizer bypass test:** submit `<xmp><img src=x onerror=alert(1)></xmp>` or an inert callback variant in a disposable lab page. Expected safe result: dropped or escaped content. Vulnerable result: sanitizer output contains active HTML rather than inert text.

## Reporting heuristics

- Show the trust-boundary crossing, not just package presence: signed attribute injection accepted by an SP, unauthenticated MCP control-plane access, credential/token material returned to a regular user, crafted evidence controlling analyst filesystem paths, or sanitized output becoming executable markup.
- Keep PoCs scoped to benign markers and lab tenants. For MCP and OpenMetadata, avoid running destructive shell/database actions; tool listing, harmless environment reads, or redacted token proof is usually enough.
- In SAML reports, include the IdP library/version, the exact profile field or claim source, the signed assertion diff, and the SP authorization decision that changed.
- In MCP reports, include bind address, transport mode, CORS/origin behavior, auth posture, reachable tool names, and the Windows user context for any harmless command proof.
- In sanitizer reports, include the sanitizer version, input payload, sanitized output, render sink, and whether the bug is stored, reflected, or admin-only.

## August 31 follow-up: OpenMetadata FreeMarker email-template SSTI to RCE (GHSA-5f29-2333-h9c7 / CVE-2026-22244)

OpenMetadata's `DefaultTemplateProvider.getTemplate()` renders email-template content fetched from the document repository into a FreeMarker `Template` with a bare `Configuration(Configuration.VERSION_2_3_31)`, no `TemplateClassResolver.SAFER_RESOLVER`, no `?api` restriction, no input sanitization. Because the template *content* is itself user-writable (an authenticated admin can replace `data.template` on any `EmailTemplate` entity via `PATCH /api/v1/docStore/{templateId}` with a `json-patch` body), a single admin credential plus any trigger that renders a notification email (test email, password reset, user invitation, account-activity notification) becomes a command execution on the server process user. This is a different trust boundary from the earlier `TEST_CONNECTION` credential-echo item on this page: there the leak is in the API *response*; here the template *content* is the payload.

- **Affected:** `org.open-metadata:platform` (maven) `>= 1.5.0, < 1.11.4`; confirmed on 1.11.2; patched in `1.11.4`.
- **Severity:** high (CWE-1336 Server-Side Template Injection).
- **Preconditions:** an authenticated admin (or any account that can `PATCH` docStore `EmailTemplate` entities), a render trigger for the modified template, and in the advisory's PoC a reachable SMTP endpoint (the advisory wired a local MailDev sink; any SMTP host works).

### Operator triage

1. Treat the docStore `EmailTemplate` PATCH endpoint as a stored-template write surface: it accepts arbitrary FreeMarker source with no restriction, so any admin-level credential is a template-authoring credential.
2. Inventory every FreeMarker/Jinja/Mustache/Go-template sink in a target that loads template content from a user-writable store (docstore, CMS, settings DB, notification queue). If the renderer is constructed without a class/built-in restriction, the stored content is a command-execution primitive, not just markup.
3. Check which notification triggers are reachable with the same credential that can write the template. A trigger that requires a *second*, lower-privilege user (e.g. the target of a password reset) matters: it means one compromised admin account can execute on behalf of flows it cannot directly drive.

### Replayable validation (lab / owned SMTP only)

Preconditions: an authorized lab OpenMetadata instance on an affected version (Docker Compose, MySQL + Elasticsearch), a lab SMTP sink (for example MailDev on `127.0.0.1:1025`) wired into the instance's email configuration, and a disposable admin account. No production instances, no real user inboxes, no exfiltration to external hosts.

1. **Positive proof is a marker in a captured email.** Log in with the lab admin token, `GET /api/v1/docStore?entityType=EmailTemplate` to find the `testMail` entity id, `PATCH` `/data/template` with an inert FreeMarker `Execute`-class marker (identity + working directory only, for example `whoami`/`pwd` equivalents or `id; pwd`), then trigger `PUT /api/v1/system/email/test` to a lab address on the lab SMTP sink. Vulnerable result: the marker output appears in the captured `.eml`.
2. **Capture the trust-boundary chain:** the `PATCH` request/response, the stored template row, the exact FreeMarker `Configuration` construction in the affected build (no `SAFER_RESOLVER`/`?api` restrictions), and the render call site in `DefaultTemplateProvider`.
3. **Negative control:** repeat the same patch + trigger against `1.11.4` (or a build with the sandboxed `Configuration`) and record that the marker no longer executes.
4. **Evidence limits:** identity/working-directory markers only. Do not capture environment-variable dumps, secrets, database credentials, or JWT signing keys in evidence; do not open reverse shells or reach cloud metadata; keep the SMTP sink local.

### Durable lesson

- **Stored template content is the payload.** Whenever template *source* is fetched from a user-writable store and compiled without a class/built-in resolver restriction, template injection is as durable a pattern as SQLi in this class of application. The audit question is "who can write the template, and what can the renderer execute", not "can I inject into a variable."
- **The admin-write + notify-render split is the report's core.** A strong report shows the write endpoint, the stored template, the unsandboxed renderer, and a single trigger that crosses from admin state to process execution, with version ranges and the sandboxed-config negative control.

## Notes on skipped items from this scan

- The androidqf and MVT path-traversal advisories are useful for forensic-tool hardening but do not add durable pentest/red-team operator guidance for the public Skillz surface.
- The Klever-Go read-only execution side-effect advisory is interesting for blockchain VM reviews, but it is too ecosystem-specific for a standalone Skillz page until a broader smart-contract VM boundary pattern emerges.
