# Hono JSX, n8n workflow, Flowise token, and Picklescan scanner-boundary checks

Source: hourly offensive-security scan, 2026-06-24, with n8n follow-ups on 2026-07-08, 2026-07-20, and 2026-07-22 and Hono follow-ups on 2026-07-21. Primary entries: GitHub Advisory Database [GHSA-458j-xx4x-4375](https://github.com/advisories/GHSA-458j-xx4x-4375), [GHSA-q4fm-pjq6-m63g](https://github.com/advisories/GHSA-q4fm-pjq6-m63g), [GHSA-f3f2-mcxc-pwjx](https://github.com/advisories/GHSA-f3f2-mcxc-pwjx), [GHSA-pmqw-72cg-wx85](https://github.com/advisories/GHSA-pmqw-72cg-wx85), [GHSA-6pcv-j4jx-m4vx](https://github.com/advisories/GHSA-6pcv-j4jx-m4vx), [GHSA-m7mq-85xj-9x33](https://github.com/advisories/GHSA-m7mq-85xj-9x33), [GHSA-9c4c-g95m-c8cp](https://github.com/advisories/GHSA-9c4c-g95m-c8cp), [GHSA-8r4j-24qv-fmq9](https://github.com/advisories/GHSA-8r4j-24qv-fmq9), [GHSA-3vg9-h568-4w9m](https://github.com/advisories/GHSA-3vg9-h568-4w9m), [GHSA-xgm2-5f3f-mvvc](https://github.com/advisories/GHSA-xgm2-5f3f-mvvc), [GHSA-frvp-7c67-39w9](https://github.com/advisories/GHSA-frvp-7c67-39w9), [GHSA-hvrm-45r6-mjfj](https://github.com/advisories/GHSA-hvrm-45r6-mjfj), and [GHSA-w62v-xxxg-mg59](https://github.com/advisories/GHSA-w62v-xxxg-mg59).

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
| [GHSA-3vg9-h568-4w9m](https://github.com/advisories/GHSA-3vg9-h568-4w9m) / CVE-2025-71354 | Picklescan `< 0.0.29` | `idlelib.debugobj.ObjectTreeItem.SetText` gave another scanner-missed callable surface for pickle execution | Maintain scanner-bypass regression corpora for Python stdlib gadget variants before trusting model or checkpoint ingestion gates; include `0.0.29+` as the patched control. |

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
- Run the scanner first, record whether each file is flagged, then load only inside the isolated VM if the test requires execution confirmation. Compare the affected release with Picklescan `0.0.29` or newer for the `ObjectTreeItem.SetText` case.
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

## July 21 Hono adapter parser-differential follow-up

The late feed adds two adapter-specific checks that complement the JSX render boundary:

| Advisory | Affected path | Durable operator boundary |
| --- | --- | --- |
| [GHSA-xgm2-5f3f-mvvc](https://github.com/advisories/GHSA-xgm2-5f3f-mvvc) / CVE-2026-59897 | Hono 4.3.3 through 4.12.26 on AWS API Gateway v1 or VPC Lattice adapters | Repeated request-header values are de-duplicated with substring matching, so one distinct value can disappear before IP-chain, routing, rate-limit, or audit logic sees it. |
| [GHSA-frvp-7c67-39w9](https://github.com/advisories/GHSA-frvp-7c67-39w9) | `@hono/node-server` before 2.0.5 on Windows; same root pattern as core Hono [GHSA-wwfh-h76j-fc44](https://github.com/advisories/GHSA-wwfh-h76j-fc44) | `%5C` remains one URL-router segment but becomes a filesystem separator after decoding, allowing a static request to enter a prefix-protected subtree without running its middleware. The read remains inside the configured static root. |

### Repeated-header loss matrix

Use a deployed adapter fixture rather than a Node-only Hono server: the vulnerable conversion occurs in API Gateway v1 or VPC Lattice request adaptation. Send the same harmless header name multiple times with distinct values where one is a substring of another, for example synthetic address markers ending in `.1` and `.10`. Capture the raw edge event, `multiValueHeaders`, adapter-produced Hono request headers, application-visible ordered values, and final marker-only decision. Compare reversed value order, non-overlapping values, API Gateway v2 or direct Node handling, Hono 4.12.26, and 4.12.27.

Report **edge receives two distinct repeated values -> substring de-duplication drops one -> application policy sees an incomplete chain**. Do not spoof real client addresses, evade a production allowlist/rate limit, or poison audit evidence. A package version alone is insufficient: prove the API Gateway v1 or VPC Lattice adapter and a security-relevant consumer of the complete list.

### Windows encoded-backslash route/filesystem split

In a disposable Windows fixture, create a static root with `public.txt` and a nested `admin/secret-canary.txt`. Mount harmless deny or authentication middleware on `/admin/*`, then request normal slash, literal backslash, `%5C`, `%255C`, and mixed-case encoding variants through the actual Node adapter. Record raw target, router segments, middleware marker, decoded filesystem path, response status, and returned canary. Repeat on the patched adapter, another OS, and a route that uses `/admin/secret-canary.txt` normally.

Positive evidence is **`/admin%5Csecret-canary.txt` treated as one route segment -> `/admin/*` middleware does not run -> Windows resolves the decoded backslash into the nested static file**. Do not claim root escape, arbitrary host-file read, or universal traversal: `..` remains blocked and the confirmed boundary stays inside the configured static root. Use only a synthetic marker file; never read application config, source, credentials, or user files.

## July 21 Hono request-context and `cx()` SSR follow-up

Two Hono 4.12.27 fixes add distinct server-rendering boundaries:

| Advisory | Affected path | Durable operator boundary |
| --- | --- | --- |
| [GHSA-hvrm-45r6-mjfj](https://github.com/advisories/GHSA-hvrm-45r6-mjfj) / CVE-2026-59896 | Hono 4.11.8 through 4.12.26; async SSR components using `createContext()`/`useContext()` or `jsxRenderer`/`useRequestContext()` | Process-wide context state can cross between concurrent renders when context is read after an `await`, mixing request identity, rendered data, or authorization state. |
| [GHSA-w62v-xxxg-mg59](https://github.com/advisories/GHSA-w62v-xxxg-mg59) / CVE-2026-59895 | Hono 4.0.0 through 4.12.26; server-side JSX where untrusted text enters `hono/css` `cx()` | `cx()` marks composed class text as already escaped without escaping it, so a quote can leave the `class` attribute and alter SSR markup. |

### Deterministic concurrent-context harness

Build a two-user lab route whose provider stores only a synthetic request ID, role marker, and output canary. Inside one async component, wait on a controllable barrier and call `useContext()` or `useRequestContext()` only after the barrier. Start request A, pause it after provider entry, run request B into the same point, then resume them in both orders. Capture request IDs at ingress, provider values, pre- and post-await context reads, response canaries, authorization-marker decisions, timing, and Hono version.

Positive evidence is **request A provider -> await suspension -> request B changes shared context -> A resumes with B's synthetic marker**. Add synchronous rendering, context read before `await`, sequential requests, one-request concurrency, and Hono 4.12.27 as controls. Use no real sessions, profile data, prompts, or tenant content. Do not rely on probabilistic load alone when barriers can produce a replayable schedule.

### `cx()` class-value escaping matrix

Trace an actual request-controlled value into `cx(baseClass, untrustedClass)` and then into a server-rendered JSX `class` attribute. Compare a normal class token, whitespace, a quote/tag-boundary canary that creates only an inert `data-*` marker, direct JSX interpolation without `cx()`, client-side DOM rendering, and Hono 4.12.27. Save the input bytes, `cx()` return type/escape flag, raw rendered HTML, parsed DOM attributes, and browser marker result.

Report **untrusted class text -> `cx()` labels the composition pre-escaped -> SSR skips attribute escaping -> inert DOM structure changes**. The application must actually allow user input to reach `cx()`; package version or use of Hono CSS alone is not enough. Never collect cookies, trigger authenticated actions, persist a payload for real users, or use an external script source.

## July 21 Flowise upload-file fallback traversal follow-up

[GHSA-99pg-hqvx-r4gf](https://github.com/advisories/GHSA-99pg-hqvx-r4gf) adds a storage fallback boundary in Flowise 3.0.5. The unauthenticated `/api/v1/get-upload-file` and `/api/v1/openai-assistants-file/download` paths validate `chatflowId` and sanitize `fileName`, but do not validate `chatId`. If the first organization-scoped file path misses, fallback logic rebuilds and checks a different path without repeating the original storage-root containment decision. A valid chatflow UUID is still a precondition; do not treat it as inherently enumerable.

Use Flowise 3.0.5 in a disposable instance with a synthetic organization, one canary chatflow, a temporary storage root, and one harmless marker file immediately outside that storage root. Submit normal and traversal-shaped `chatId` values to both download routes while holding `chatflowId` and `fileName` constant. Capture route, method, authentication state, normalized primary path, normalized fallback path, response hash, and any fallback copy/delete side effects. Compare Flowise 3.0.6, an invalid UUID, a missing marker, and a normal in-root upload.

Positive evidence is **unvalidated `chatId` -> fallback path is rebuilt after the containment check -> only the synthetic adjacent marker is returned or moved**. Stop there. Never request `database.sqlite`, `.env`, API keys, prompts, uploaded documents, credentials, or user files; never run this against production because the fallback can move/delete the source and disrupt later storage operations. If chatflow-ID disclosure is assessed separately, use only a lab UUID and field-presence evidence rather than verbose production paths.

## July 22 n8n agent, Git, browser, and credential-artifact follow-up

Five n8n advisories add reusable checks across low-code agent authorization, repository path races, browser preview isolation, navigation schemes, and JWT construction. The four general n8n issues affect releases before `1.123.64`, the 2.x line before `2.29.8`, and `2.30.0`; the AI Agents role issue affects releases before `2.29.8` and `2.30.0`. Confirm the exact advisory range rather than treating every n8n deployment as reachable.

| Advisory | Preconditions | Durable operator boundary |
| --- | --- | --- |
| [GHSA-x5vx-c2c8-m3w9](https://github.com/advisories/GHSA-x5vx-c2c8-m3w9) / CVE-2026-65015 | AI Agents enabled; a Project Viewer can chat with an agent whose node tools are enabled | `agent:execute` authorization did not re-check node-execution or project-credential authority, so a read-only project member could invoke tools with stronger project capabilities. |
| [GHSA-g3r5-9h93-4j2c](https://github.com/advisories/GHSA-g3r5-9h93-4j2c) / CVE-2026-65598 | Authenticated workflow author can run the Git clone node; a restart/load cycle is part of the affected path | Path validation and clone use were separated by a TOCTOU window, allowing a directory-to-symlink swap to redirect the clone into the community-node load path. |
| [GHSA-p3rg-hrf9-w9gj](https://github.com/advisories/GHSA-p3rg-hrf9-w9gj) / CVE-2026-65597 | Member-controlled execution output reaches HTML preview and another user opens it | Unsandboxed `iframe srcdoc` made sanitizer failure a same-origin editor sink instead of an isolated preview. |
| [GHSA-9wcp-9r3j-383q](https://github.com/advisories/GHSA-9wcp-9r3j-383q) / CVE-2026-65592 | Workflow author controls persisted Resource Locator metadata and a viewer follows its external-link action | `cachedResultUrl` reached `window.open()` without scheme validation, creating a stored workflow-metadata-to-navigation boundary. |
| [GHSA-9r8p-h6cc-6qhm](https://github.com/advisories/GHSA-9r8p-h6cc-6qhm) / CVE-2026-65599 | Google Service Account credentials are configured and the generated assertion is observable in an owned test integration | The full PEM private key was placed in the base64url-encoded JWT `kid` header instead of a non-secret key identifier. |

### AI Agent viewer-to-tool authority matrix

Create a disposable project with Owner, Editor, and Viewer users, one AI Agent, and one inert node tool that returns only a fixed marker. Give the project a fake credential used solely by an owned callback. Compare direct node execution, ordinary workflow execution, and agent-chat tool invocation for each role. Record caller role, project membership, agent scope, selected tool, credential owner, authorization response, callback marker, and n8n version.

Positive evidence is **Viewer denied direct execution -> Viewer asks the project agent to use the node tool -> tool runs under project authority or uses the fake project credential**. Stop at the inert marker. Do not enable shell, SSH, filesystem, spending, messaging, or production connector tools, and do not ask the agent to reveal credential values.

### Git clone TOCTOU confinement harness

Use a disposable n8n process, scratch Git repository, temporary community-node directory, and an adjacent marker-only destination. Instrument the lab so the path check and clone operation can be paused deterministically; do not depend on a probabilistic race against a shared service. After validation but before clone use, replace only the checked scratch directory with a symlink to the marker destination. Record the validated path, filesystem identity before and after the barrier, final clone destination, and whether a benign custom node marker is detected after an isolated restart.

The proof is **allowed path validated -> directory identity changes -> clone follows the replacement link -> inert marker lands in the community-node path**. Never race a production instance, overwrite an installed node, load untrusted JavaScript, or use a repository containing executable behavior. A directory marker and load-path observation are sufficient; host command execution is not required.

### Preview and Resource Locator browser matrix

For HTML preview, create execution output containing only an inert DOM marker that distinguishes top-level same-origin access from a sandboxed frame. Capture the generated `iframe` attributes, `srcdoc`, origin behavior, parsed DOM, and whether the marker can reach a synthetic parent-page field. Compare ordinary text preview, a sandboxed local fixture, and a patched n8n release.

For Resource Locator, store normal `https:`, relative, malformed, and non-network scheme canaries in `cachedResultUrl`, then invoke the same external-link UI action a real viewer would use. Instrument `window.open()` in the lab to record the exact URL and block navigation. Positive evidence is an unsafe scheme reaching that sink, not script execution. Do not read cookies, call authenticated APIs, persist payloads for real users, or navigate to third-party origins.

### Google service-account JWT header check

Generate a disposable service-account-style key pair that has no cloud permissions and send the assertion only to an owned mock token endpoint. Decode the JWT header locally and compare expected `kid` shape, observed field length/type, and whether the unique fake PEM marker is present. Preserve only a redacted header shape or hash of the marker in the report; delete the test key after the run.

Report **credential object -> JWT constructor -> secret bytes in base64url header -> owned observer can recover the fake marker**. Do not inspect production proxy logs, use a real Google service-account key, or attempt cloud impersonation. Base64url decoding the assertion header is sufficient to prove exposure.

## Reporting notes

- Lead with the crossed boundary: **object key to SSR attribute name**, **workflow editor to public form visitor**, **workflow metadata to SQL identifier**, **shared workflow editor to another user's credential reference**, **project viewer to credentialed agent tool**, **validated Git path to replaced filesystem object**, **execution output to same-origin preview**, **persisted locator URL to browser navigation**, **service-account key to observable JWT header**, **unauthenticated org selector to OAuth secret**, **default token key to tenant metadata**, **import JSON to SQL/path sink**, **unvalidated chat ID to fallback file path**, **scanner verdict to unsafe pickle load**, **repeated edge header to incomplete application-visible list**, **URL segment to Windows filesystem separator**, **one request's async JSX context to another response**, or **untrusted class text to pre-escaped SSR markup**.
- Include exact package, version, route/node/API, user role, and the canary value used. These are preconditioned findings; versionless or roleless reports will be weak.
- Keep proof artifacts disposable and redacted: lab forms, scratch schemas, synthetic OAuth providers, fake tenant IDs, imported canary flows, and offline pickle files.
- Adjacent updated-feed items for ImageMagick memory/resource issues and Flowise password-salt weakness were tracked but not promoted because they were availability/resource-hardening or did not add a stronger offensive validation workflow than the Flowise token and secret-boundary items above.

## Late July 22 n8n identity, credential, node, and filesystem boundary wave

The next n8n advisory wave broadens the same workflow-authority model. Do not test from version presence alone: first prove the named feature, node, caller role, and configuration. Fixed-version lines vary across the wave; use each linked advisory, with common fixed releases including `1.123.64` or `1.123.67`, `2.29.8`, `2.30.1`, `2.31.5`, and `2.32.1`.

### Identity and API authority

| Advisory | Boundary to validate |
| --- | --- |
| [GHSA-mq3m-f8x3-579w](https://github.com/advisories/GHSA-mq3m-f8x3-579w) / CVE-2026-59208 | Multiple trusted token issuers were collapsed onto a local account by `sub` alone instead of the `(iss, sub)` pair. |
| [GHSA-8342-988q-86cr](https://github.com/advisories/GHSA-8342-988q-86cr) | Embed login accepted an email claim without requiring verified-email semantics or enforcing the trusted key's role ceiling. |
| [GHSA-35q8-9mj6-wjmf](https://github.com/advisories/GHSA-35q8-9mj6-wjmf) / CVE-2026-65016 | Enterprise SSO instance-role provisioning could map an IdP-controlled claim to `global:owner` when the optional provisioning flag was enabled. |
| [GHSA-777w-rpr6-c52h](https://github.com/advisories/GHSA-777w-rpr6-c52h) / CVE-2026-65595 | Token-exchange JWTs received all Public API scopes rather than scopes bounded by the acting user's role. |
| [GHSA-75qm-gp28-rcq9](https://github.com/advisories/GHSA-75qm-gp28-rcq9) / CVE-2026-59206 | Dangerous workflow credential keys could alter object behavior and expose unauthenticated user/project enumeration responses. |

Build an identity matrix with two synthetic issuers that deliberately reuse one subject, verified and unverified canary emails, low/high role claims, and a disposable local account per expected identity. Exercise only harmless profile/status and marker-only Public API routes. Capture issuer, subject, email-verification state, trusted-key role ceiling, provisioned local identity, resulting API scopes, and fixed-version result. Never impersonate real users, create production admins, install packages, delete users, or reuse live tokens.

### Shared credentials and destination policy

| Advisory | Boundary to validate |
| --- | --- |
| [GHSA-q3j5-8vrg-4p9q](https://github.com/advisories/GHSA-q3j5-8vrg-4p9q) / CVE-2026-59209 | HTTP Request pagination expressions could steer later requests and carry a shared credential header to an unintended owned destination. |
| [GHSA-h44j-f5r5-ph73](https://github.com/advisories/GHSA-h44j-f5r5-ph73) / CVE-2026-59207 and [GHSA-64xh-79j6-r5v8](https://github.com/advisories/GHSA-64xh-79j6-r5v8) | AI Agent MCP connectors and several AI/LLM nodes did not enforce a shared credential's allowed-domain restriction against user-selected endpoints. |
| [GHSA-6qc9-mqvw-jg7x](https://github.com/advisories/GHSA-6qc9-mqvw-jg7x) | An expression in HTTP Request `genericAuthType` was checked before resolution, skipping ownership validation for a known credential ID. |
| [GHSA-cj9h-qx8g-pq2g](https://github.com/advisories/GHSA-cj9h-qx8g-pq2g) | Inline JSON in Execute Sub-workflow hid nested credential references from top-level save-time and runtime checks. |

Use two disposable editors, a shared fake credential containing a unique inert header, and two owned callback origins. Compare direct HTTP Request, pagination, AI/LLM endpoint override, MCP connector, resolved versus expression-backed `genericAuthType`, and inline versus referenced sub-workflows. A positive proof is the fake header arriving at the wrong owned origin or an unauthorized reference being accepted. Do not recover the credential value from storage, target third-party APIs, or use production secrets.

### Execution, outbound-fetch, and file boundaries

| Advisory | Boundary to validate |
| --- | --- |
| [GHSA-pm35-fqvh-cq5g](https://github.com/advisories/GHSA-pm35-fqvh-cq5g) / CVE-2026-65591 and [GHSA-gv7g-jm28-cr3m](https://github.com/advisories/GHSA-gv7g-jm28-cr3m) | Legacy computed-member and VM arrow-function expression paths crossed their intended expression sandboxes. |
| [GHSA-9w78-79q7-r4fp](https://github.com/advisories/GHSA-9w78-79q7-r4fp) / CVE-2026-65593 | Any authenticated user could reach dynamic-node-parameter routes and replace a declared base URL with an absolute URL. |
| [GHSA-vhf8-cg2h-cg3p](https://github.com/advisories/GHSA-vhf8-cg2h-cg3p) | MCP Client requests bypassed enabled SSRF filtering and address pinning. |
| [GHSA-gf29-4f56-r2jf](https://github.com/advisories/GHSA-gf29-4f56-r2jf) | Git fetch, pull, and push-tags accepted local repositories outside `N8N_RESTRICT_FILE_ACCESS_TO`. |
| [GHSA-rcv6-pvrj-4xcg](https://github.com/advisories/GHSA-rcv6-pvrj-4xcg) | A staged local repository could make the Git node execute repository hooks under default Git behavior. |
| [GHSA-2x35-3fw4-9jr4](https://github.com/advisories/GHSA-2x35-3fw4-9jr4) | A webhook-derived non-string Send Email body became a Nodemailer content object and selected a local path or URL. |
| [GHSA-xmc9-4f2h-jf9c](https://github.com/advisories/GHSA-xmc9-4f2h-jf9c) | Edit Image passed an unvalidated output format into the image backend, allowing a write outside its working directory. |
| [GHSA-pf2q-pxhf-hgmw](https://github.com/advisories/GHSA-pf2q-pxhf-hgmw) | `@n8n/computer-use` `search_files` patterns expanded beyond the configured base directory. |

For expressions and Git hooks, use an inert temp-file marker in an isolated n8n container; host-shell access or persistence is unnecessary. For URL paths, use an owned callback and a synthetic loopback service created for the test—never metadata or real internal services. For Git and file checks, place unique marker repositories/files immediately outside disposable roots and prove only the path crossing. For Send Email, use fake SMTP plus synthetic local/URL content; for Edit Image, write only a disposable marker; for `search_files`, return only a known adjacent canary file.

The strongest report names the exact transition: **external identity to wrong local account**, **low role to global API scopes**, **shared credential to disallowed origin**, **nested or unresolved node metadata to another user's credential**, **workflow expression to process marker**, **declared service base URL to owned callback**, **allowed Git workspace to adjacent repository or hook**, **non-string message field to local/URL content**, **image format to output path**, or **search pattern to outside-base canary**. Availability-only prototype-pollution advisories in the same wave were tracked but not promoted as standalone workflows.
