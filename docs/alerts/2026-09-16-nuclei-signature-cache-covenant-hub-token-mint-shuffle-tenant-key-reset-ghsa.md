# Scanner, C2, and SOAR control-plane trust boundaries: Nuclei signature-cache mtime bypass, Covenant unauthenticated SignalR hub token mint, Shuffle cross-tenant API-key reset (3 GHSAs)

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-09-16 (unreviewed wave published 2026-09-16T18:32Z).

Shared axis: **the control plane of an offensive/automation tool is itself an unauthenticated attack surface.** A scanner's signature-verification cache trusts file mtime, a C2 framework's WebSocket hub skips the auth attribute its REST API enforces and mints operator tokens, and a SOAR platform's admin endpoint resets API keys for arbitrary user IDs across tenant boundaries. Each of these changes what you can trust about a tool you deploy on engagements.

## Advisory table

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-77rj-h8wx-6cgq](https://github.com/advisories/GHSA-77rj-h8wx-6cgq) | CVE-2026-92718 | high (7.3) | **Nuclei < 3.11.1**: template signature verification is cached based on **file modification time only, without content checksums**. An attacker who can replace verified template files swaps in unsigned malicious content and restores the original mtime to pass the signature check → arbitrary OS command execution when the operator next runs a scan. Template-directory write access = code execution on the scanner host, defeating the signature gate entirely. |
| [GHSA-h9hg-x52x-c465](https://github.com/advisories/GHSA-h9hg-x52x-c465) | — | critical | **Covenant ≤ 0.6**: the `CovenantHub` SignalR hub is registered **without an `[Authorize]` attribute**, so unauthenticated callers can invoke `CreateHttpListener` and receive a **signed JWT token**. That token authenticates against the entire operator API — grunts, credentials, binaries, events, and the operator roster. The WebSocket hub family bypassed the auth gate the REST surface enforces. |
| [GHSA-gxxx-83g3-wgp9](https://github.com/advisories/GHSA-gxxx-83g3-wgp9) | — | high | **Shuffle ≤ 2.2.1**: `HandleApiGeneration` lets an administrator of **any organization** reset and read API keys for **arbitrary user IDs in other organizations** (cross-tenant privilege escalation → account takeover). Delegated credential-generation endpoints accepted the caller's org-admin role but never bound the target user to the caller's tenant. |

## Why this is worth an operator page

- **Your scanner is a supply-chain target with a broken verification gate.** Nuclei templates execute code (DSL expressions, JS helpers, shell-backed helpers) on the operator's machine. The mtime-only signature cache means anyone with write access to the templates directory — a shared runner, a compromised repo sync, a malicious PR to a forked template set — can persist payloads that survive the signature check by restoring mtime (`touch -r`). This is the scanner-side twin of the wiki's existing untrusted-template-execution guidance: previously the risk was running untrusted templates; now even "verified" templates can be silently swapped.
- **C2 infrastructure: enumerate hubs, not just routes.** Covenant's SignalR hub skipped exactly one attribute (`[Authorize]`) that the REST API enforced, and the exposed method *issues valid tokens*. For red-teamers this is both an acquisition lesson (a blue team that finds your Covenant hub naked owns your whole campaign — grunts, exfil, operator roster) and a target-side lesson (defensive C2 frameworks you encounter may expose the same hub-vs-route auth drift). WebSocket/SignalR/hub route families are a distinct authorization surface from HTTP routes on any ASP.NET-family control plane.
- **Shuffle is a bug-hunt pattern, not just a Shuffle bug**: "admin-scoped action endpoint that takes a target user ID without tenant binding." Any multi-tenant SOAR/workflow/automation platform with an admin "reset/regenerate API key" action must be tested with a second disposable organization. Same axis as the wiki's existing cross-tenant API-key and delegated-CRUD entries.
- **Alternate-transport auth parity keeps winning.** The Covenant record is the latest in a long wiki series (djust WS/SSE fail-open, Mattermost WebSocket revocation staleness, MCP local transports) where the non-REST transport — WebSocket hub, SSE, SignalR — skips the middleware/attribute the REST stack enforces.

## Validation workflows (authorized scope only)

!!! warning "Lab instances, disposable tenants, inert payloads only"
    Prove each boundary on deployments you own with disposable orgs/users, inert template markers, and lab C2 infrastructure. Never swap live production scanner templates, never point testing at third-party Covenant/Shuffle instances, never collect real credentials.

### 1. Nuclei template-cache integrity check (own tooling)

1. Inventory every machine that runs Nuclei and note the engine version; < 3.11.1 is the exposed window.
2. Check template-directory ownership/permissions: who can write `~/.local/nuclei-templates` (or your mirrored/pinned template path)?
3. Self-test on a lab runner (fixed version for the negative control): place an inert marker template (harmless `http` matcher, no shell helpers), record its mtime, edit content, restore mtime with `touch -r <original-ref> <file>`, re-run — on vulnerable versions the signature cache does not re-verify. Use only inert matchers; never test with shell-executing templates.
4. Upgrade to ≥ 3.11.1 and repeat as the negative control.
5. Reporting heuristic: report as **"signature verification cache keyed on mtime allows template substitution with restored timestamp → code execution on scanner host"** with the mtime-restore command as the PoC step, not the payload.

### 2. C2 hub-surface audit (your own infrastructure)

1. From the engagement network, attempt a SignalR/WebSocket negotiation against your Covenant (or similar) control panel's hub paths without credentials.
2. Positive (vulnerable): the hub accepts the handshake and exposes invokable methods. Do **not** invoke token-minting methods against anything you do not own; on your own instance, confirm only that the unauthenticated method list is reachable, then patch to > 0.6.
3. Generalize into an engagement checklist for any ASP.NET-family control plane you operate: enumerate `/hubs/*` and WebSocket endpoints separately from REST routes and diff the auth posture.
4. Blue-team-acquisition awareness: treat an exposed hub as full-campaign compromise when scoping blast radius of a C2 seizure.

### 3. Cross-tenant API-key regeneration check (Shuffle-style platforms)

1. Create two disposable organizations (A and B) with one non-admin user each.
2. As org-A admin, call the API-key generation/reset endpoint with org B's user ID.
3. Positive: key is regenerated and returned. Prove only with the disposable users' keys; record the exact role claimed, the target user's tenant, and the returned key material **redacted** (presence + prefix only).
4. Re-check the fixed version (2.2.2+) with the same call as negative control.

## Tracked, not published this run

Sparse/product-specific records from the same 18:32Z unreviewed wave reviewed and skipped: Kubero unauthenticated notifications API (GHSA-m69f-42c6-7334, single-product credential read; credential-store-reachability axis already covered), Scirius PCAP upload `_id` traversal (GHSA-h754-2546-79g9, path-traversal-to-.json axis covered by the archive/file-write pages), Quickwit `queue_url` unvalidated host/scheme SSRF (GHSA-rx45-hj8g-x4vm, generic SSRF), IRIS case-comment authz (defensive IR tooling), Concrete CMS quartet (folded into the [Sept 16 route-authorization page](2026-09-16-saml-tenant-claim-mcp-metadata-jsonapi-marketplace-and-route-authorization-ghsa.md)), AEM/kkFileView/Guns/Ruijie/SourceCodester/GPAC/MuPDF/Open5GS/Sogou singles (no reusable operator pattern beyond existing pages), Dell Update Package Framework stack overflow + DRM default permissions (hygiene singles). KEV gained Acronis Backup cPanel/Plesk plugin default-permissions LPE (CVE-2026-87886) — tracked as shared-hosting-plugin hygiene on the existing [LiteSpeed cPanel boundary page](2026-06-20-jce-litespeed-cisco-kev-boundaries.md)'s axis; not standalone operator guidance.

## Safety constraints

- Do not substitute real templates into production scanner installs; inert marker templates only, on disposable runners.
- Do not exercise hub methods or key-regeneration endpoints against third-party or production systems.
- Never include live C2 tokens, real API keys, or tenant credentials in reports — presence proofs only.

## Related

- [Nuclei template update hygiene](../best-practices/nuclei-template-update-hygiene.md)
- [Agent, sandbox, tool, and secret-boundary batch (Nuclei DSL env disclosure, JS require file read)](2026-05-11-agent-sandbox-tool-and-secret-boundary-batch-ghsa.md)
- [Sept 16 identity-assertion / route-authorization late wave](2026-09-16-saml-tenant-claim-mcp-metadata-jsonapi-marketplace-and-route-authorization-ghsa.md)
- [JCE profile upload, LiteSpeed cPanel symlink, and Cisco SD-WAN file-write boundary checks](2026-06-20-jce-litespeed-cisco-kev-boundaries.md)
