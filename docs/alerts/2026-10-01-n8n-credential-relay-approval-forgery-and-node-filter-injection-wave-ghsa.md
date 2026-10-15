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

## October 5 follow-up: header-spoofed approval-link steering captures the resume capability token (Heym, folded)

- **Heym before 0.0.112 token leakage via spoofed `Origin`/`X-Forwarded-Host`** ([CVE-2026-105396 / GHSA-84cp-gph2-pv3x](https://github.com/advisories/GHSA-84cp-gph2-pv3x), medium): `build_public_base_url()` constructs HITL review-link URLs from request-supplied host material with no validation. An unauthenticated attacker triggers an anonymous workflow with forged headers, so the **human reviewer's notification link points at the attacker's domain** — and the URL embeds a capability token whose holder gets to submit the decision, which then executes **with the workflow owner's credentials**. The attacker captures the token from their own access log and replays it: approval forgery without ever touching the real app.
- Durable axis extending §2: the approval/resume token rides *inside the link*, and the link's **base URL is assembled from untrusted request data** in a large share of self-hosted tools (behind-proxy apps deriving public URLs from `X-Forwarded-Host` are the fingerprint). Sweep: on any tool with email/IM approval notifications, send yourself a review request and diff the minted link's host against (a) a forged `X-Forwarded-Host`, (b) a doubled `Host` header, (c) `Origin`-derived variants. If the notification link follows the header, the capability token in it is deliverable to an attacker log — report as token-theft-to-decision-execution, not "open redirect."
- Second-order lesson for report writing: the header bug is the *delivery* leg; the impact sentence is "attacker approves guarded actions as the workflow owner." Pair this with the Sept 19 password-reset-link origin-trust family (TYPO3 reset-link page) — same base-URL-from-headers root cause, but where reset links carry a credential to *your* account, approval links carry a credential to *act for* someone else, which is the higher-value target on agent/HITL platforms.
- Bounded validation: own Heym (or any HITL tool) instance, your own workflow, your own second listener domain; prove with an echoed link-host diff and a decision submitted via the captured token against a synthetic pending action you own; never route a real reviewer's notification anywhere.

## 5. Fold-ready adjacency

The same wave also carried **Budibase AI-table SSRF** ([CVE-2026-103757 / GHSA-2524-3r74-44wr](https://github.com/advisories/GHSA-2524-3r74-44wr): AI table generation's `uploadUrl` calls raw `node-fetch` instead of the platform's `fetchWithBlacklist`, so an attachment-column URL in a prompt makes the server fetch internal endpoints and echo them back via a presigned object-storage URL — folded on the [Oct 1 http-client guard-coverage page](2026-10-01-http-client-adapter-guard-coverage-drift-axios-1-20-wave-ghsa.md); Budibase pages already live on this wiki), and **Obot MCP deny-list omission** ([CVE-2026-103758 / GHSA-x6jv-4hp7-3vj9](https://github.com/advisories/GHSA-x6jv-4hp7-3vj9): `checkUI` deny list misses `/mcp-connect-composite/` → Basic-role users proxy tool calls to ACL-restricted MCP servers — folded on the [Oct 1 MCP trust-layers page](2026-10-01-mcp-gateway-session-client-browser-bridge-and-agent-prompt-injection-cluster-ghsa.md)).

## October 15 follow-up: sixteen-leg wave — path-segment auth, inline-definition credential bypass, validator prototype poisoning, and field-allowlist drift (CVE-2026-110840..110853)

A second coordinated n8n wave published **fifteen n8n advisories plus the Heym sibling** at 00:31Z (fixed 1.123.83 / 2.41.4 / 2.42.1). This is the second n8n wave on this page — the same-product re-sweep rule keeps paying. New axes beyond §1–§4:

| Advisory | New axis |
| --- | --- |
| [CVE-2026-110852 / GHSA-g529-fwwh-f6vf](https://github.com/advisories/GHSA-g529-fwwh-f6vf) (medium) | **Dynamic-path webhook resolution matched on the path alone, ignoring the server-generated identifier segment** — omit the unguessable UUID from webhook/form/MCP route URLs and the workflow still executes, **under the owning project's credentials**, unauthenticated, for *any* project. The secret URL segment was auth material that the resolver never required. |
| [CVE-2026-110846 / GHSA-vp7q-xcmw-hq44](https://github.com/advisories/GHSA-vp7q-xcmw-hq44) (high) | Waiting-webhook signature bypass: Send-and-Wait validation is selected **before normalizing an alternate node-reference form** — validation-before-normalization order bug; a resume-token holder approves *others'* waiting executions, running downstream actions (potentially command execution) under the workflow owner's credentials. Extends §2: the normalization-order family (compare the Oct 14 NGINX `StripPrefix`/normalization rule) hits approval gates. |
| [CVE-2026-110844 / GHSA-v42g-p7pc-xq95](https://github.com/advisories/GHSA-v42g-p7pc-xq95) (high) + [CVE-2026-110850 / GHSA-fv6m-3pmx-fcmp](https://github.com/advisories/GHSA-fv6m-3pmx-fcmp) (high) | Save-time credential authorization **inspects only a node's top-level `credentials` field** — inline Workflow Tool/Retriever sub-workflow definitions and Message-an-Agent node tool parameters can reference credential IDs the editor cannot access; they execute with the **owner's decrypted secrets**, exfiltrable to an attacker-chosen destination. Field-level authz that doesn't recurse into nested/inline JSON is a no-op. |
| [CVE-2026-110853 / GHSA-9mgf-2q6c-j3gw](https://github.com/advisories/GHSA-9mgf-2q6c-j3gw) (high) | Execute-Sub-workflow in **inline JSON mode accepts a caller-supplied trusted workflow identifier** → resolve credentials from projects you don't belong to + write another workflow's static data / error-workflow dispatch. Same either-end/identity-spoof family as the PraisonAI dependency-edge rule. |
| [CVE-2026-110842 / GHSA-fm6v-qhr5-4c32](https://github.com/advisories/GHSA-fm6v-qhr5-4c32) (high) | MCP workflow-validation tool **evaluates caller-supplied code in the main process**, reads inherited properties, allows prototype assignment — a `workflow:read`-only member replaces a built-in method with a truthy-returning one so **server-side permission checks accept scopes the caller doesn't hold**, enabling takeover of owner accounts not protected by MFA. A validator that executes input is an auth bypass waiting for prototype pollution. |
| [CVE-2026-110848 / GHSA-v3wp-jvw4-xcp3](https://github.com/advisories/GHSA-v3wp-jvw4-xcp3) (medium) | AI workflow builder merges connections keyed by **node name** without reserved-key checks → `__proto__` node name pollutes global prototype (DoS-until-restart leg of the same prototype-chain root cause). |
| [CVE-2026-110841 / GHSA-v38m-4hx4-9x2r](https://github.com/advisories/GHSA-v38m-4hx4-9x2r) (medium) | Agent chat resume endpoint takes a **run identifier from the body with no checkpoint-ownership check** — project members read other members' private agent conversations and **approve their pending tool calls**, tools executing and writing into the victim's conversation. Resume-endpoint identity binding, §2 rule again. |
| [CVE-2026-110851 / GHSA-wrfc-h8h3-x3xj](https://github.com/advisories/GHSA-wrfc-h8h3-x3xj) (medium) | Agents create endpoint checks permission **against the requested project, not the owning project of the supplied Agent ID** → read-only members relocate and rewrite Agents across projects (authorize-the-owner-not-the-request-container, Gitea attachment twin). |
| [CVE-2026-110849 / GHSA-m7pg-rcp8-66vv](https://github.com/advisories/GHSA-m7pg-rcp8-66vv) + [CVE-2026-110847 / GHSA-q529-cjvg-c6m6](https://github.com/advisories/GHSA-q529-cjvg-c6m6) (high) | Stored XSS legs: file-preview modal **re-publishes binary data as an unsandboxed same-origin blob URL** (member upload → script on the *owner's* session when they preview); hosted-chat page interpolates unsanitised `customCss` into markup on an **authentication-free published page**, executing on the instance origin against signed-in visitors. Preview/render surfaces and unauthenticated published artifacts are XSS targets even when the editor UI is trusted. |
| [CVE-2026-110845 / GHSA-qgh4-pf6j-6hwh](https://github.com/advisories/GHSA-qgh4-pf6j-6hwh) (high) | Git node Log operation **fails to strip the repository's local git config before invoking external programs** — point the node (including as an agent tool) at a repo whose local config you control → execution as the n8n process user. Same `core.*`-from-cloned-repo family as the Aug 25 GitPython config legs and the June 22 TeamCity submodule-URL leg. |
| [CVE-2026-110840 / GHSA-f8fm-f8xf-2rfr](https://github.com/advisories/GHSA-f8fm-f8xf-2rfr) (high) | MS SQL node v1 substitutes **Query-field expression values directly into SQL text** — a workflow that binds webhook fields to Query lets unauthenticated external callers run arbitrary SQL with the stored credential's privileges. §3 rule reaching a new node. |
| [CVE-2026-110843 / GHSA-8fm5-rv7r-2xfg](https://github.com/advisories/GHSA-8fm5-rv7r-2xfg) (high) | Unauthenticated OAuth authorize endpoint resolves clients by URL path but **stores the raw identifier including query string as the record key** — identifiers differing only in `?query` mint unlimited first-party client records past the registration cap. Canonicalization-mismatch on *write keys* (§ canonicalization family, now registration-abuse). |
| Heym [CVE-2026-110873 / GHSA-wh8c-wx4r-x3rj](https://github.com/advisories/GHSA-wh8c-wx4r-x3rj) (high) | Shared collaborators can overwrite `error_workflow_id` because the field is **missing from `OWNER_ONLY_EXECUTION_FIELDS`** — repoint the error workflow to your own workflow with an HTTP node; when the parent errors, **the owner's decrypted credentials are injected and sent to you**. Field-allowlist drift on execution-affecting fields: enumerate every field that changes *where code/credentials flow*, diff against the owner-only set, don't just test the obvious config fields. (Heym's Oct 5 resume-token leg already lives on this page — same product, second promotion = re-sweep validated.) |

Operator rules added by this wave:

1. **Unguessable-path-segment-as-authentication sweep**: on any webhook/callback API, delete the secret path segment and see if resolution falls back to matching on attacker-known fields (path slug, workflow name). If yes, the secret was decoration.
2. **Recursion rule for save-time field authz**: any ownership/permission check on structured payloads (workflow JSON, agent configs, IaC) must be probed at *every nesting level* — top-level `credentials` passing while inline sub-definitions/tools carry references is the standard bypass shape.
3. **Prototype-chain battery on validator tools**: where a server evaluates user-supplied expressions to make an authorization decision, test `__proto__` pollution and inherited-property reads as scope-upgrade primitives, not just as crash DoS.
4. **Execution-affecting field inventory**: `error_workflow_id`-style fields (error handlers, retry targets, resume targets, dispatch destinations) are capability-granting; list them per product and test write access from every lower role.

## Evidence and reporting checklist

- [ ] Exact n8n version line (1.x vs 2.x fix ranges differ per advisory).
- [ ] For relay proofs: the marker value your listener received, the scope field you manipulated, and proof your lab user lacked that scope.
- [ ] For injection proofs: the widened-query row count vs single-record control; never export real tenant rows.
- [ ] For approval proofs: the guarded action's inert sink (a logging node), not the production side effect.
- [ ] Keep credential values, chat histories, and webhook payloads out of report evidence; record field names and presence booleans only.

Related pages: [Sept 21 automation-platform credential relay](2026-09-21-automation-platform-credential-test-exfil-and-fqdn-endpoint-metadata-ssrf-ghsa.md) (controller test-button twin), [Sept 23 payment webhook per-branch signatures](2026-09-23-woocommerce-payment-webhook-branch-and-amount-integrity-cluster-ghsa.md), [Oct 1 http-client guard coverage](2026-10-01-http-client-adapter-guard-coverage-drift-axios-1-20-wave-ghsa.md), [May 14 Flowise/n8n tenant workflow boundaries](2026-05-14-flowise-and-n8n-tenant-workflow-boundary-batch-ghsa.md).
