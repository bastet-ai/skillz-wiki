---
title: n8n credential relay, approval forgery, and node filter-injection wave (Oct 1 12:31Z)
---

# n8n credential relay, approval forgery, and node filter-injection wave

A single October 1 12:31Z GitHub advisory wave published **seventeen n8n advisories** (fixed 1.123.80 / 2.39.6 / 2.40.1). One product, one wave, but the cluster is the most complete public map yet of where workflow-automation platforms break: credential material relay, approval-gate integrity, third-party-node query injection, webhook signature coverage, and a queue-mode supply chain. If you test any automation platform (n8n, Node-RED, Automatisch, Activepieces, Flowise, PraisonAI), this is the test matrix.

Primary sources (all [github.com/advisories](https://github.com/advisories), GHSA links inline below).

!!! warning "Disposable instances and owned sinks only"
    Use a lab n8n with synthetic users, projects, credentials (values = random markers), and workflows. Every exfiltration sink is an **owned listener** that records and denies. Never touch shared instances, real credential values, real chat histories, or production Redis. Package-install proofs use an inert marker package on a private index you control.

## 1. Credential relay: the platform is the confused deputy

Five of the seventeen advisories are the same shape — an endpoint that **fetches or decrypts credential material and hands it somewhere the caller chose**:

| Advisory | Relay leg |
| --- | --- |
| [CVE-2026-103252 / GHSA-r56q-6p4g-65g7](https://github.com/advisories/GHSA-r56q-6p4g-65g7) (high) | **Credential test endpoint resolves project-scoped variables without validating caller access to the project** — put an arbitrary project ID in the request body and the server interpolates that project's sensitive variables into a credential-test request sent to your host. Test-button = cross-tenant secret relay. |
| [CVE-2026-103246 / GHSA-6w8v-v5w3-7x56](https://github.com/advisories/GHSA-6w8v-v5w3-7x56) (high) | Inline agent node-tool introspection accepts **arbitrary credential IDs** — decrypts and returns plaintext secrets to an attacker-controlled host with no ownership check. |
| [CVE-2026-103256 / GHSA-6m32-557f-fqq9](https://github.com/advisories/GHSA-6m32-557f-fqq9) (high) | Wekan/Baserow username-password credentials send **unencrypted passwords to an unvalidated host field** — anyone with credential-update permission repoints the host and receives accounts. |
| [CVE-2026-103259 / GHSA-qrhv-fqjc-jcmq](https://github.com/advisories/GHSA-qrhv-fqjc-jcmq) (high) | Dynamic Credentials authorize/revoke endpoints let a **resolver-registration capability set the fallback resolver to an attacker endpoint** during account connection → collaborator session tokens captured. |
| [CVE-2026-103247 / GHSA-v9vf-c827-9m93](https://github.com/advisories/GHSA-v9vf-c827-9m93) (medium) | Tamper guard matches credentials by **node name, not node ID** — duplicate node IDs in a shared workflow retain the victim's credential binding while the visible config is yours → secrets ride to your host. |

Operator sweep for any low-code/automation platform:

1. Enumerate every endpoint that *uses* credentials: test/verify buttons, node introspection, dry-run/preview, connection wizards, resolver/registration flows.
2. For each, vary three inputs independently: **target URL/host**, **credential/variable/project ID you don't own**, **workspace/project scoping field**. Positive = your listener receives marker-value secret material while your lab user holds no membership in the owning scope.
3. For save/edit guards, always test the **identity-key mismatch** (name vs id, UUID vs slug) that lets a benign-looking edit preserve a dangerous binding.

## 2. Approval gates are state transitions — test who can advance them

- [CVE-2026-103260 / GHSA-v8hf-6rg3-94j4](https://github.com/advisories/GHSA-v8hf-6rg3-94j4) (medium): Send-and-Wait "Approve Within Chat" **resume requests verify neither requester identity nor approval permission** — an unauthenticated user can advance a waiting execution and fire the guarded action behind it.
- [CVE-2026-103254 / GHSA-w2h3-gf8c-fwgw](https://github.com/advisories/GHSA-w2h3-gf8c-fwgw) (high): signed approval **resume-URL generation** takes caller-controlled node IDs and the containment check misses **unresolved traversal sequences** — mint valid approval URLs for gates in projects you cannot access (cross-project approval forgery *through a signed artifact*).
- [CVE-2026-103245 / GHSA-f4rh-5hw6-wc66](https://github.com/advisories/GHSA-f4rh-5hw6-wc66) (medium): Webflow Trigger webhook handler **never verifies the x-webflow-signature HMAC** — forge trigger payloads, drive workflows, manipulate downstream record creation.

Durable axes: (1) the **resume token** for an approval gate is a credential — check identity binding at the resume sink, not just at gate creation; (2) **signed ≠ scoped**: re-run traversal/canary proofs against signed-URL generators because signing often covers the value but not the *ownership* of the inputs used to build it; (3) webhook signature coverage is per-trigger-node — on any platform with N integration triggers, forged-payload each one (this mirrors the Sept 23 payment-gateway per-branch rule).

## 3. Third-party nodes are where the query layer goes untyped

Seven advisories are node-level injection where workflow-bound parameters cross into query languages without escaping — the same class as the Fleet filter-key and ClickHouse filter-key precedents, now at ecosystem scale:

| Node | Injection |
| --- | --- |
| Supabase [CVE-2026-103248 / GHSA-c6j4-7wv3-xqf9](https://github.com/advisories/GHSA-c6j4-7wv3-xqf9) | Filters (String) mode doesn't escape field values → filter-expression injection turns one-row lookup into **read-all / update-all / delete-all in a single request** |
| Supabase [CVE-2026-103255 / GHSA-34g6-xwv9-46f3](https://github.com/advisories/GHSA-34g6-xwv9-46f3) | `tableId` interpolated into request **paths** → traverse to Auth/Storage APIs **with the serviceRole key, bypassing Row Level Security** — the admin key re-uses tenant-facing routes |
| MongoDB Chat Memory [CVE-2026-103250 / GHSA-gpvq-4wmp-cp47](https://github.com/advisories/GHSA-gpvq-4wmp-cp47) | `sessionId` accepts **Mongo query operators** (`$gt`, `$regex`) — unauthenticated cross-user chat-history read + write/delete |
| Oracle DB [CVE-2026-103253 / GHSA-4p39-vh7m-r689](https://github.com/advisories/GHSA-4p39-vh7m-r689) | Single quotes in table/schema fields of Delete Table Drop → appended DDL/DML at the credential's privileges |
| SendGrid/Freshservice/ServiceNow [CVE-2026-103258 / GHSA-fr2j-m9j7-53r7](https://github.com/advisories/GHSA-fr2j-m9j7-53r7) | Unescaped parameter interpolation breaks out of query literals → single-record lookups widen to match-all (contact lists, tickets, directories) |
| n8n node [CVE-2026-103257 / GHSA-cfpw-gmwr-v9wc](https://github.com/advisories/GHSA-cfpw-gmwr-v9wc) | Unvalidated **resource identifiers** redirect API calls to unintended resources within the key's scope |
| Resource Locator dropdown [CVE-2026-103249 / GHSA-7g6m-6jgv-fqm4](https://github.com/advisories/GHSA-7g6m-6jgv-fqm4) | Stored DOM XSS via injected script URLs in dropdown link handling; **persists across workflow imports and shares** → editor-origin JS against whoever opens the node |

Audit rule for any node-based platform: bind a node parameter to **untrusted upstream input** (webhook body, chat message) and ask what grammar the parameter enters — PostgREST filter strings, Mongo operator objects, SQL identifiers, REST paths. A parameter that a UI treats as a *value* but the node concatenates as *syntax* is the finding. Then test the **operator-object shape** everywhere an ID is expected (`{"$gt":""}` in a JSON body) — that single canary cracked the chat-memory boundary unauthenticated.

## 4. Queue-mode Redis is an unauthenticated package-install control plane

[CVE-2026-103251 / GHSA-c2h5-4pr8-j687](https://github.com/advisories/GHSA-c2h5-4pr8-j687) (high): in queue mode, the community-package install handler trusts work queued through **Redis** — write access to Redis alone bypasses name validation, permission checks, checksum verification, and npm safety checks, installing arbitrary npm packages **across every worker in the cluster**. Post-access recon/replay rule: on any queue-mode worker architecture (Bull/BullMQ, Celery, Sidekiq, RQ), the broker is a privilege boundary — enumerate what jobs and control messages a bare broker write can enqueue, and whether consumers validate the queue contents. Prove with an inert marker package from a private index in a lab, never against shared infrastructure.

## 5. Fold-ready adjacency

The same wave also carried **Budibase AI-table SSRF** ([CVE-2026-103757 / GHSA-2524-3r74-44wr](https://github.com/advisories/GHSA-2524-3r74-44wr): AI table generation's `uploadUrl` calls raw `node-fetch` instead of the platform's `fetchWithBlacklist`, so an attachment-column URL in a prompt makes the server fetch internal endpoints and echo them back via a presigned object-storage URL — folded on the [Oct 1 http-client guard-coverage page](2026-10-01-http-client-adapter-guard-coverage-drift-axios-1-20-wave-ghsa.md); Budibase pages already live on this wiki), and **Obot MCP deny-list omission** ([CVE-2026-103758 / GHSA-x6jv-4hp7-3vj9](https://github.com/advisories/GHSA-x6jv-4hp7-3vj9): `checkUI` deny list misses `/mcp-connect-composite/` → Basic-role users proxy tool calls to ACL-restricted MCP servers — folded on the [Oct 1 MCP trust-layers page](2026-10-01-mcp-gateway-session-client-browser-bridge-and-agent-prompt-injection-cluster-ghsa.md)).

## Evidence and reporting checklist

- [ ] Exact n8n version line (1.x vs 2.x fix ranges differ per advisory).
- [ ] For relay proofs: the marker value your listener received, the scope field you manipulated, and proof your lab user lacked that scope.
- [ ] For injection proofs: the widened-query row count vs single-record control; never export real tenant rows.
- [ ] For approval proofs: the guarded action's inert sink (a logging node), not the production side effect.
- [ ] Keep credential values, chat histories, and webhook payloads out of report evidence; record field names and presence booleans only.

Related pages: [Sept 21 automation-platform credential relay](2026-09-21-automation-platform-credential-test-exfil-and-fqdn-endpoint-metadata-ssrf-ghsa.md) (controller test-button twin), [Sept 23 payment webhook per-branch signatures](2026-09-23-woocommerce-payment-webhook-branch-and-amount-integrity-cluster-ghsa.md), [Oct 1 http-client guard coverage](2026-10-01-http-client-adapter-guard-coverage-drift-axios-1-20-wave-ghsa.md), [May 14 Flowise/n8n tenant workflow boundaries](2026-05-14-flowise-and-n8n-tenant-workflow-boundary-batch-ghsa.md).
