# Hono JSX, n8n workflow, Flowise token, and Picklescan scanner-boundary checks

Source: hourly offensive-security scan, 2026-06-24, with n8n follow-ups on 2026-07-08 and 2026-07-20. Primary entries: GitHub Advisory Database [GHSA-458j-xx4x-4375](https://github.com/advisories/GHSA-458j-xx4x-4375), [GHSA-q4fm-pjq6-m63g](https://github.com/advisories/GHSA-q4fm-pjq6-m63g), [GHSA-f3f2-mcxc-pwjx](https://github.com/advisories/GHSA-f3f2-mcxc-pwjx), [GHSA-pmqw-72cg-wx85](https://github.com/advisories/GHSA-pmqw-72cg-wx85), [GHSA-6pcv-j4jx-m4vx](https://github.com/advisories/GHSA-6pcv-j4jx-m4vx), [GHSA-m7mq-85xj-9x33](https://github.com/advisories/GHSA-m7mq-85xj-9x33), [GHSA-9c4c-g95m-c8cp](https://github.com/advisories/GHSA-9c4c-g95m-c8cp), [GHSA-8r4j-24qv-fmq9](https://github.com/advisories/GHSA-8r4j-24qv-fmq9), and [GHSA-3vg9-h568-4w9m](https://github.com/advisories/GHSA-3vg9-h568-4w9m).

These items are durable for operators because each one exposes a repeatable boundary that shows up across modern app and AI stacks: object keys crossing into SSR HTML attribute names, low-code workflow metadata crossing into browser or SQL sinks, unauthenticated org selectors returning identity-provider secrets, weak default token material enabling tenant metadata tampering, import files crossing into SQL/path construction, and scanner allowlists missing Python pickle gadget surfaces.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-458j-xx4x-4375](https://github.com/advisories/GHSA-458j-xx4x-4375) / CVE-2026-56761 | Hono `hono/jsx` SSR | JSX attribute **values** were escaped, but untrusted attribute **names** could contain whitespace, quotes, or `>` and corrupt the generated HTML | Add object-key-to-attribute-name testing to SSR reviews, especially where query/form/profile keys are spread into JSX props. |
| [GHSA-q4fm-pjq6-m63g](https://github.com/advisories/GHSA-q4fm-pjq6-m63g) / CVE-2026-56358 | n8n Form Trigger | workflow editors could store CSS-sanitization bypass payloads that execute for visitors of published forms | Treat public workflow forms as tenant-to-public-browser render sinks; prove with harmless DOM canaries and form-action observation, not credential theft. |
| [GHSA-f3f2-mcxc-pwjx](https://github.com/advisories/GHSA-f3f2-mcxc-pwjx) / CVE-2026-56351 | n8n database nodes | table and column identifiers in MySQL, PostgreSQL, and Microsoft SQL nodes were not escaped like value parameters | Test workflow database nodes with identifier canaries, not just parameter placeholders, when low-code users can configure table or column names. |
| [GHSA-pmqw-72cg-wx85](https://github.com/advisories/GHSA-pmqw-72cg-wx85) / CVE-2026-54307 | n8n shared workflows and public API endpoints | member-level workflow editors could reference credentials they did not own because ownership checks were only partially applied | Add credential-reference IDOR checks to shared-workflow tests; prove with redacted fake credentials and two disposable users, not live secret exfiltration. |
| [GHSA-6pcv-j4jx-m4vx](https://github.com/advisories/GHSA-6pcv-j4jx-m4vx) / CVE-2026-56270 | Flowise `/api/v1/loginmethod` | unauthenticated callers could supply an organization ID and retrieve SSO provider configuration, including OAuth client secrets in cleartext | Add unauthenticated organization-selector endpoints to AI-workflow recon; evidence should be field-presence/redacted-key-shape only. |
| [GHSA-m7mq-85xj-9x33](https://github.com/advisories/GHSA-m7mq-85xj-9x33) / CVE-2026-56269 | Flowise temp-token crypto | `TOKEN_HASH_SECRET` fell back to a hardcoded default used to derive encryption keys for user/workspace metadata in JWT-like temp tokens | Check SaaS/self-hosted agent platforms for default token secrets and tenant metadata that can be decrypted, modified, and re-signed in labs. |
| [GHSA-9c4c-g95m-c8cp](https://github.com/advisories/GHSA-9c4c-g95m-c8cp) / CVE-2025-71332 | Flowise import APIs | imported chatflow/tool/variable JSON let authenticated users influence IDs that reached SQL construction and path-like canvas routes | Add import/export bundles to workflow-platform boundary tests; use disposable IDs and SQL/path markers only. |
| [GHSA-8r4j-24qv-fmq9](https://github.com/advisories/GHSA-8r4j-24qv-fmq9) / CVE-2025-71361 | Picklescan | `idlelib.calltip.Calltip.fetch_tip` could be used as a pickle `__reduce__` callable that older scanner rules did not flag | Extend ML model-scanner coverage tests with inert built-in callable gadgets, not just obvious `os.system` imports. |
| [GHSA-3vg9-h568-4w9m](https://github.com/advisories/GHSA-3vg9-h568-4w9m) / CVE-2025-71354 | Picklescan | `idlelib.debugobj.ObjectTreeItem.SetText` gave another scanner-missed callable surface for pickle execution | Maintain scanner-bypass regression corpora for Python stdlib gadget variants before trusting model or checkpoint ingestion gates. |

## Operator triage

1. **Look for object-key spread into SSR.** Hono's issue is not ordinary value escaping failure; the risky path is code that turns attacker-controlled keys into attribute names, for example dynamic prop maps, profile field names, A/B-test parameters, or CMS metadata rendered with JSX spread.
2. **Separate workflow author from workflow visitor, database, and credential owner.** In n8n, the attacker may be an authenticated workflow editor, while the impacted surface is a published form, database action, or credential reference owned by another user.
3. **Inventory organization-selector APIs.** Flowise-style login/bootstrap endpoints often must be reachable before authentication. Test whether `organizationId`, workspace slug, or tenant domain selectors return secrets, provider metadata, or cross-tenant configuration.
4. **Check default cryptographic material in deployed configs.** A weak default token secret matters when token claims carry user, workspace, or organization identifiers that are accepted as authorization context.
5. **Treat import bundles as executable policy.** Flowise imports cross from JSON into database IDs, route paths, and stored workflow state. Include import endpoints in tenant-boundary and SQLi reviews.
6. **Do not trust a single ML scanner verdict.** Picklescan bypasses are useful because they show where scanner rules can lag behind Python's callable surface. Use multiple scanners, static review, and inert custom canaries before loading untrusted pickles.

## Replayable validation boundaries

### Hono JSX attribute-name injection

- Preconditions: owned Hono app or lab route using `hono/jsx` SSR and an application path where request-controlled keys become JSX prop names.
- Use a harmless attribute-key canary such as a quoted marker, whitespace marker, or tag-boundary marker that should render as text if safely rejected or encoded.
- Capture the rendered HTML diff: normal key, malformed key, and patched/rejected behavior when available.
- Do not attempt credential theft, session actions, or persistent payloads. The proof is attribute/tag structure corruption from an attacker-controlled key.

### n8n form and database-node boundaries

- Preconditions: n8n lab, disposable workflow editor account, published test form, and disposable database credential connected to a scratch schema.
- For Form Trigger, store a benign style/DOM canary and observe only execution or form-action mutation on the published form. Do not collect visitor tokens, cookies, submissions, or secrets.
- For database nodes, compare value-parameter escaping with identifier handling by using synthetic table/column names in a scratch database. Capture the generated query effect through marker rows or controlled error messages.
- Keep evidence to workflow ID, node type, role, route, canary marker, and patched negative control.

### n8n shared-workflow credential-reference boundary

- Preconditions: n8n lab with workflow sharing enabled, two disposable users, one workflow shared to a member-level user as editor, and fake credentials whose values are unique canaries.
- Enumerate the public API paths that let a workflow editor create, update, import, or execute nodes that reference credential IDs. Compare UI ownership checks with raw API behavior.
- Attempt to attach or reference only the other disposable user's fake credential ID. Evidence should stop at whether the API accepts the reference or whether a controlled workflow can use the canary credential against an owned callback endpoint.
- Record caller role, workflow ownership, credential owner, endpoint, request field carrying the credential ID, expected denial, and actual result.
- Do not test against production credentials, external SaaS tokens, customer workflows, or real third-party integrations. A strong proof uses inert tokens and an owned callback that receives a harmless marker.

### Flowise loginmethod, token, and import boundaries

- Preconditions: Flowise lab or explicitly scoped tenant, disposable organizations/workspaces, synthetic SSO providers, and no production OAuth credentials.
- For `/api/v1/loginmethod`, query only lab organization IDs and redact all secret values. A strong proof shows unauthenticated access and the presence of sensitive fields, not live credential use.
- For weak token secrets, create a lab token with known `TOKEN_HASH_SECRET` unset, decrypt or modify only synthetic user/workspace IDs, and verify whether the application accepts the altered token for a harmless route.
- For import APIs, import JSON with canary IDs that exercise SQL identifier/path handling against disposable chatflows/tools/variables. Do not read or overwrite production workflows.

### Picklescan scanner-bypass regression

- Preconditions: offline test VM, disposable pickle/model files, affected and patched scanner versions, and no production model-loading workers.
- Build a regression corpus around inert callables that only print a marker or write to a temporary file in the test VM. Include `idlelib.calltip.Calltip.fetch_tip` and `idlelib.debugobj.ObjectTreeItem.SetText` variants without destructive commands.
- Run the scanner first, record whether each file is flagged, then load only inside the isolated VM if the test requires execution confirmation.
- Evidence should be a scanner decision matrix and marker-only execution proof. Never publish payloads that read files, environment variables, cloud credentials, notebooks, or model weights.

## July 20 n8n webhook, sandbox, repository, and database follow-up

The updated feed added eight n8n advisories that fit the same workflow-authority model:

| Advisory | Boundary worth testing |
| --- | --- |
| [GHSA-2vff-hj5x-8gq7](https://github.com/advisories/GHSA-2vff-hj5x-8gq7) / CVE-2026-54306 | A public webhook body could prototype-pollute copied workflow data, then make credentialed downstream nodes act on attacker-supplied fields as a confused deputy. |
| [GHSA-v733-mwr6-fgcm](https://github.com/advisories/GHSA-v733-mwr6-fgcm) / CVE-2026-54301 | A workflow editor could return binary content with an attacker-selected `Content-Type` while bypassing the central CSP sandbox header, creating active same-origin content for authenticated visitors. |
| [GHSA-jvc7-762p-3743](https://github.com/advisories/GHSA-jvc7-762p-3743) / CVE-2026-54308 | Microsoft Agent 365 and Stripe trigger routes accepted forged events when the webhook URL was known because the expected inbound token or signature was not validated. |
| [GHSA-5xp3-2w67-427v](https://github.com/advisories/GHSA-5xp3-2w67-427v) / CVE-2026-49465 | Git clone and push operations accepted local repository paths outside `N8N_RESTRICT_FILE_ACCESS_TO`, letting an editor relay repository contents into an allowed location. |
| [GHSA-9pq8-m8gp-4p53](https://github.com/advisories/GHSA-9pq8-m8gp-4p53) / CVE-2026-49444 | A Python Code node could escape the Python Task Runner sandbox when that optional runner was enabled. |
| [GHSA-9c38-2mcm-q7f7](https://github.com/advisories/GHSA-9c38-2mcm-q7f7) / CVE-2026-54311 | The Merge node's cached SQL sandbox allowed one workflow author's prototype changes to persist into another project or user's later execution. |
| [GHSA-jpq7-226w-6cxx](https://github.com/advisories/GHSA-jpq7-226w-6cxx) / CVE-2026-54313 | MongoDB Find And Replace treated an editor-controlled value as a query filter, allowing operator-shaped input to match and overwrite unintended scratch documents. |
| [GHSA-c37g-w77q-m4vp](https://github.com/advisories/GHSA-c37g-w77q-m4vp) / CVE-2026-54310 | TimescaleDB and legacy PostgreSQL v1 node parameters crossed into SQL structure instead of remaining bound values. |

### Replayable n8n lab workflow

1. Use a disposable multi-user n8n instance with no production credentials. Create separate author A, author B, and visitor accounts, an owned callback service, a scratch Git repository, and scratch MongoDB/PostgreSQL databases.
2. **Public webhook confused deputy:** build a test webhook that copies request data into a downstream HTTP action. Send a normal marker and a dangerous-key marker such as a nested `__proto__` field. A safe positive proof is the owned callback receiving an unintended marker field; do not target third-party records or use real connector credentials.
3. **Trigger authenticity:** capture a legitimate synthetic Stripe or Microsoft Agent 365 event shape, remove or alter its signature/token, and replay it only to the lab trigger URL. Record whether the workflow runs, whether the event is rejected, and the patched negative control.
4. **Webhook response origin:** configure `Respond to Webhook` to return inert binary content with an HTML-like content type. Compare CSP and browser rendering between normal and binary response paths. Stop at a harmless DOM marker; never read cookies, tokens, or authenticated page data.
5. **Git file sandbox:** place a marker-only Git repository just outside the configured allowed root. Test clone-from-local and push-to-local paths, then verify only whether the marker repository becomes reachable inside the allowed scratch directory. Do not target source trees, home directories, credentials, or production repositories.
6. **Python runner:** execute a marker-only sandbox regression in a throwaway task-runner container. Evidence should be a temp-file marker inside that disposable container and the runner configuration/version; do not open a shell, access the host, or make outbound requests.
7. **Cross-project Merge state:** have author A submit an inert prototype marker through Merge SQL mode, then execute author B's workflow with a unique synthetic row. The finding is persistence or observation of the marker across execution contexts, not collection of another tenant's real workflow data.
8. **Database nodes:** use seeded scratch rows and compare scalar values, identifier fields, limits, and operator-shaped filter objects. Record generated-query effects through marker rows and expected-vs-actual match sets. Never point the workflow at production databases.

For reports, name the exact authority jump: **unauthenticated webhook body to credentialed action**, **workflow editor to same-origin visitor**, **unsigned provider event to workflow execution**, **local Git path to sandboxed file view**, **code-node author to task-runner execution**, **cached sandbox state to another project**, or **node parameter to database query structure**. Include the node version, caller role, route or operation, canary, and patched negative control.

## Reporting notes

- Lead with the crossed boundary: **object key to SSR attribute name**, **workflow editor to public form visitor**, **workflow metadata to SQL identifier**, **shared workflow editor to another user's credential reference**, **unauthenticated org selector to OAuth secret**, **default token key to tenant metadata**, **import JSON to SQL/path sink**, or **scanner verdict to unsafe pickle load**.
- Include exact package, version, route/node/API, user role, and the canary value used. These are preconditioned findings; versionless or roleless reports will be weak.
- Keep proof artifacts disposable and redacted: lab forms, scratch schemas, synthetic OAuth providers, fake tenant IDs, imported canary flows, and offline pickle files.
- Adjacent updated-feed items for ImageMagick memory/resource issues and Flowise password-salt weakness were tracked but not promoted because they were availability/resource-hardening or did not add a stronger offensive validation workflow than the Flowise token and secret-boundary items above.
