# Langflow, Mailpit, Outerbase, Miniflux, and render-boundary checks

Source: hourly offensive-security scan, 2026-06-19; updated 2026-06-23 for the Langflow monitor API ownership issue, 2026-07-07 for Langflow [CVE-2026-55255](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) KEV user-controlled-key authorization bypass, and 2026-07-20 for public-playground and knowledge-base boundaries. Primary entries: GitHub advisories [GHSA-wwf9-7jrc-rv4q](https://github.com/advisories/GHSA-wwf9-7jrc-rv4q), [GHSA-ccv6-r384-xp75](https://github.com/advisories/GHSA-ccv6-r384-xp75), [GHSA-qrpv-q767-xqq2](https://github.com/advisories/GHSA-qrpv-q767-xqq2), [GHSA-9c59-2mvc-vfr8](https://github.com/advisories/GHSA-9c59-2mvc-vfr8), [GHSA-w4mc-hhc6-xp28](https://github.com/advisories/GHSA-w4mc-hhc6-xp28), [GHSA-m999-j542-5w3r](https://github.com/advisories/GHSA-m999-j542-5w3r), [GHSA-7h5p-637f-jfr7](https://github.com/advisories/GHSA-7h5p-637f-jfr7), and [GHSA-c29q-5xm7-5p62](https://github.com/advisories/GHSA-c29q-5xm7-5p62).

This batch is durable because each issue maps to a repeatable web-app or AI-workflow boundary: user-controlled dashboard widgets rendered with application tokens in scope, Langflow node configuration crossing into local file reads and execution-capable flows, response and monitor IDs crossing tenant/user ownership checks, mail-link preview APIs missing address-canonicalization coverage, redirect targets bypassing URL policy, and MediaWiki extension template variables crossing into stored HTML.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-wwf9-7jrc-rv4q | Outerbase Studio text widgets | dashboard-authored text widget content rendered in a token-bearing application origin | Treat collaborative dashboard/report widgets as active token-adjacent content; prove with harmless DOM markers and disposable sessions. |
| GHSA-ccv6-r384-xp75 | Langflow `BaseFileComponent` nodes | flow/node configuration could cross into arbitrary local file reads and execution-capable chains | Audit AI workflow builders for file-component parameters, tool chaining, and server-side execution context with synthetic canary files only. |
| GHSA-qrpv-q767-xqq2 | Langflow `/api/v1/responses` | authenticated response IDs were not adequately scoped to the requesting user/flow | Add object-ownership checks to AI workflow response/history APIs; prove with two disposable users and marker responses. |
| GHSA-9c59-2mvc-vfr8 / CVE-2026-33760 | Langflow `/api/v1/monitor` | monitor endpoints accepted `flow_id`, message IDs, and session IDs without consistently joining back to `Flow.user_id` | Extend Langflow ownership checks beyond response APIs to monitor transactions, build artifacts, message edits/deletes, and session rename/delete paths. |
| GHSA-w4mc-hhc6-xp28 | Mailpit Link Check API | SSRF protections missed IPv6 transition and address-encoding mechanisms | Extend SSRF URL-canonicalization tests beyond IPv4 literals to IPv4-mapped IPv6, 6to4/Teredo-style forms, brackets, and encoded hosts. |
| GHSA-m999-j542-5w3r | Miniflux redirect handling | redirect policy could be bypassed by crafted target URLs | Treat feed-reader and login/navigation redirects as URL-parser differentials; capture allowed-vs-denied URL matrix with owned destinations. |
| GHSA-7h5p-637f-jfr7 | StarCitizenWiki Embed Video extension | user-controlled class values reached template rendering as stored HTML | In wiki/CMS extensions, test template variables that look cosmetic, such as CSS classes, as HTML-context sinks. |
| GHSA-c29q-5xm7-5p62 | StarCitizenWiki Embed Video extension | user-controlled service names reached exception output and stored rendering | Include error paths and unsupported-provider messages in render-sink testing; do not stop at the happy-path embed template. |

## Operator triage

1. **Find whether the data is passive or executable in context.** Widgets, flow nodes, embed classes, provider names, and exception text are often treated as metadata until rendered or interpreted in a privileged origin.
2. **Use two-user ownership tests.** Langflow response and monitor APIs need a positive owner, negative non-owner, and preferably a separate flow/workspace control before claiming IDOR/BOLA.
3. **Canonicalize before SSRF or redirect claims.** Record the raw URL, parsed host, normalized address, DNS result, redirect decision, and final callback hit. Parser differentials are the core evidence.
4. **Keep AI-workflow file proofs synthetic.** Use canary files created for the assessment. Never read environment files, SSH keys, model credentials, uploaded datasets, or cloud tokens.
5. **Skip adjacent availability-only items.** Langflow multipart upload DoS and py7zr resource-exhaustion entries were not promoted here because they do not add a stronger offensive validation workflow without a target-specific chain.

## Replayable validation boundaries

### Dashboard/widget content to application-origin token scope

- Create a lab Outerbase Studio workspace with a disposable user and no production data sources.
- Add text/widget content containing inert HTML/DOM markers that prove escaping and origin context. Do not use token-exfiltration JavaScript.
- Load the dashboard as another disposable user if collaboration is in scope and record whether the marker renders in a token-bearing origin.
- Negative controls: sanitized widget renderer, isolated preview origin, CSP that blocks script execution, and widgets rendered without application tokens.

### Langflow file components, response ownership, and monitor ownership

- Build a disposable Langflow instance with two users, two flows, and a synthetic file such as `/tmp/langflow-canary.txt` owned by the test environment.
- For file-component boundaries, identify nodes inheriting from or wrapping file-read behavior and set only the synthetic canary path. Positive evidence is marker content reaching the flow result or a controlled downstream node.
- For execution-capable chains, stop at a visible inert marker or no-op node. Do not run shell payloads, read secrets, or touch production flow storage.
- For response IDOR, create response records as user A, then request the same IDs as user B. Capture status, owner fields, and marker text with all secrets redacted.
- For monitor API ownership, create two disposable users and two flows. Generate synthetic prompt/response messages and build artifacts only; then test user B against user A's `flow_id`, message IDs, and session IDs on the monitor read/update paths.
- Safe positive evidence is limited to a synthetic transaction marker, a build-artifact marker, or a controlled session rename visible in the lab. Do not delete production conversations, collect real prompts, or copy model responses from live tenants.

### Mailpit link-check SSRF canonicalization

- Use an owned callback server and a lab Mailpit instance with no access to production networks.
- Test the same destination represented as hostname, IPv4, IPv6 bracket literal, IPv4-mapped IPv6, 6to4/Teredo-like representation, decimal/octal/hex IPv4, URL-encoded host, and redirect chain.
- Positive evidence is a callback or route-status change for a representation that should have been blocked by the configured policy.
- Do not target cloud metadata endpoints, internal services, RFC1918 production addresses, or tenant infrastructure.

### Redirect URL-policy differentials

- Use owned domains for allowed and disallowed destinations.
- Build a matrix covering scheme case, userinfo, backslashes, encoded slashes, control characters, double-encoded components, punycode, suffix hosts, and nested redirect parameters.
- Record both parser output and browser-followed destination. A redirect bypass report needs a concrete security boundary such as login flow, OAuth return, feed action, or privileged navigation.

### Wiki/CMS extension render sinks

- Use a lab wiki/CMS and a page or embed record controlled by the test account.
- Test variables that feed CSS classes, service/provider names, captions, exception messages, and fallback templates with harmless DOM markers.
- Include unsupported-service and validation-error paths; many render bugs live in error output rather than normal templates.
- Do not publish payloads that steal cookies, administrator tokens, or cross-site request tokens; show marker rendering and context instead.

## July 7 Langflow user-controlled-key auth-bypass KEV follow-up

CISA added [CVE-2026-55255](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to KEV on 2026-07-07 as a Langflow authorization-bypass issue through a user-controlled key. Treat this as an adjacent Langflow API ownership/key-binding workflow rather than a separate generic alert.

Operator validation stays inside the existing two-user Langflow lab:

- Create user A and user B, each with separate flows, sessions, response history, monitor entries, API keys or share keys, and any workspace-scoped objects exposed by the target version.
- For every endpoint that accepts a caller-supplied key, ID, token, `flow_id`, message ID, session ID, project/workspace ID, or share key, test whether the server derives ownership from trusted session context or from the user-controlled parameter.
- Safe positive evidence is a synthetic object marker, controlled route-state change, or redacted metadata field from user A becoming visible or mutable to user B.
- Negative controls should include a patched version, an unrelated random key, a valid key bound to the wrong user, and a valid key with a mismatched flow/workspace ID.
- Do not collect real prompts, model outputs, uploaded documents, vector-store contents, API keys, environment variables, or tenant data.

Add this boundary name to reports when it applies: **caller-controlled Langflow key to cross-user or cross-workspace authorization context**.

## July 20 public-playground and knowledge-base follow-up

Three updated Langflow advisories add a useful distinction between a flow being intentionally public and every execution-time field being trusted:

- [GHSA-v5ff-9q35-q26f](https://github.com/advisories/GHSA-v5ff-9q35-q26f) / CVE-2026-48519: the unauthenticated `/api/v1/build_public_tmp` path accepted attacker-supplied custom component code in the public execution graph. A shared flow therefore crossed from **public invocation** to **caller-controlled server-side code**.
- [GHSA-rcjh-r59h-gq37](https://github.com/advisories/GHSA-rcjh-r59h-gq37) / CVE-2026-48520: the same public execution request accepted a `files` list that could name local or configured S3 objects and feed their bytes into the model path. Exposure depended on the flow and model configuration, so prove the complete return path rather than claiming universal file disclosure.
- [GHSA-79ph-745m-6wxq](https://github.com/advisories/GHSA-79ph-745m-6wxq) / CVE-2026-42867: authenticated knowledge-base creation used the caller-controlled `name` in filesystem paths, allowing traversal or absolute paths to place Langflow-generated metadata outside the caller's knowledge-base root.

### Shareable-playground differential

1. Create a disposable Langflow lab, a minimal public flow, and a unique public flow ID. Keep the instance isolated from production networks and credentials.
2. Capture one normal `/api/v1/build_public_tmp/<flow-id>/flow` request from the shareable playground. Preserve it as the positive control rather than reconstructing undocumented request fields from memory.
3. For graph integrity, alter only a custom-component code field in the submitted graph so it returns a fixed marker or raises a recognizable exception. Do not run shell commands, import process/network helpers, or access environment data.
4. For file handling, create a synthetic local image/text canary and, if S3 storage is part of scope, a disposable canary object. Change only the request's `files` entry and observe whether the marker reaches the model input or returned flow output.
5. Record three separate facts: whether the path was accepted, whether the file was opened, and whether bytes were returned to the unauthenticated caller. Do not infer disclosure from a successful request alone.
6. Negative controls: a non-public flow ID, an unrelated random ID, a patched release, an out-of-root path that should be denied, and a public request whose submitted graph differs from the stored graph.

### Knowledge-base path containment

1. Use two disposable Langflow users and a temporary storage root. Seed each user's knowledge-base directory with distinct non-sensitive markers.
2. Submit normal, `../` traversal, sibling-prefix, encoded-separator, and absolute-path `name` values to `POST /api/v1/knowledge_bases`. Target only a disposable canary directory outside the expected knowledge-base root.
3. Check whether directories, `embedding_metadata.json`, or `schema.json` appear at the canary target. Capture path resolution and before/after directory listings; do not overwrite an existing knowledge base or application file.
4. Compare the affected behavior with a patched version that performs component-aware containment, not string-prefix matching.

Report these as **public invocation to caller-supplied execution graph**, **public file selector to model-mediated file return**, or **knowledge-base name to outside-root metadata write**. Include the exact route, public/authenticated state, storage backend, flow composition, marker-only evidence, and negative controls. Never read real local files, buckets, prompts, API keys, model credentials, or another tenant's knowledge-base data.

## July 21 unauthenticated `exec_globals` validation-route KEV follow-up

CISA added [CVE-2026-0770](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to KEV on 2026-07-21. The primary [ZDI advisory](https://www.zerodayinitiative.com/advisories/ZDI-26-036/) identifies an unauthenticated Langflow validation endpoint whose `exec_globals` parameter can include attacker-controlled functionality and execute in the server context. Langflow 1.9.0 is the vendor release referenced by CISA.

Keep validation marker-only because this route is unauthenticated and exploitation has been observed:

1. Use an isolated Langflow lab with no production credentials, mounted secrets, cloud role, sensitive flows, or unrestricted egress.
2. Capture the normal request schema for the affected validation route from the exact lab version. Confirm authentication state with no cookie/header, a malformed credential, and a disposable authenticated user.
3. Change only `exec_globals` so the validation result exposes a fixed in-memory marker or benign type/value. Do not import process, filesystem, socket, package-loader, or environment helpers and do not run a shell command.
4. Record whether the field is accepted, whether the marker becomes available to evaluated code, and which service identity handles the request. A validation error alone does not prove execution.
5. Compare Langflow 1.9.0 or later and a control that strips the field or binds globals server-side.

Report **unauthenticated validation input -> caller-controlled `exec_globals` -> inert server-side evaluation marker**. Do not publish executable payloads, read environment variables, or test an internet-facing production instance.

## July 30 MCP environment and build-job ownership follow-up

Two IBM Langflow OSS records covering 1.0.0 through 1.10.1 extend the existing execution and two-user authorization workflows:

- [GHSA-gx45-8jc3-gqqr / CVE-2026-12940](https://github.com/advisories/GHSA-gx45-8jc3-gqqr) states that the MCP stdio launcher used a dangerous-environment-variable blocklist that omitted `SHELLOPTS`, `BASHOPTS`, and `PS4`. Treat this as **request-controlled environment to interpreter startup behavior**, not as a reason to run a shell payload.
- [GHSA-xxrp-rxf8-3mmx / CVE-2026-12945](https://github.com/advisories/GHSA-xxrp-rxf8-3mmx) states that authenticated users could access or manipulate another user's build jobs through log retrieval and unauthenticated build endpoints.

### MCP stdio environment recorder

1. Run an isolated Langflow build with no credentials, sensitive environment, network egress, or production MCP servers. Replace the stdio child program with a recorder that serializes received argv and environment-key names, writes one temp marker, and exits; it must not invoke a shell.
2. Capture a normal MCP stdio launch from the product UI/API. Change only benign values for ordinary variables and the three named shell-control variables. Use fixed strings with no commands, substitutions, paths, or callbacks.
3. Record request field, validation/blocklist decision, environment map reaching the child-process API, selected executable, argv, and recorder marker. Never print inherited environment values.
4. Compare omitted variables, a blocked named variable, direct `env` object input versus nested configuration, and a corrected build or allowlist-only wrapper.
5. A bounded positive is **unauthenticated/request-controlled MCP launch field -> named shell-control variable survives policy -> recorder child receives it**. This proves policy reachability; do not claim code execution unless an approved no-op interpreter harness separately proves a startup behavior change.

### Build-job ownership matrix

Create build jobs for users A and B with synthetic logs and artifact markers. Test list, status, log retrieval, cancellation, update, and unauthenticated build routes independently. As B, submit A's already known lab job ID; then repeat without credentials, with a random ID, wrong flow/workspace, owner A, administrator, and corrected build. Capture route, authentication state, actor, job owner, action, marker returned, state transition, and handler authorization decision.

Strong evidence is **foreign build-job ID -> ownership is not joined to actor/flow/workspace -> synthetic log marker is returned or harmless job state changes**. Do not retrieve real prompts, generated code, environment output, build artifacts, credentials, or another tenant's production jobs.

## Reporting notes

- Name the crossed boundary precisely: **widget content to token-bearing dashboard origin**, **AI file-node parameter to server file read**, **flow response ID to another user's history**, **monitor `flow_id` to another user's transaction/build logs**, **message/session ID to cross-user history mutation**, **caller-controlled Langflow key to cross-user authorization context**, **unauthenticated `exec_globals` to server-side validation context**, **IPv6 transition URL to link-check SSRF**, **redirect parser bypass to privileged navigation**, **embed class to stored HTML**, or **provider error text to stored HTML**.
- Include version, authentication role, workspace/tenant IDs, URL parser normalization, network callback evidence, and negative controls. Keep evidence to synthetic markers and owned infrastructure.

## July 28 FAISS namespace ownership follow-up

[GHSA-668j-2f6w-gqwr / CVE-2026-13442](https://github.com/advisories/GHSA-668j-2f6w-gqwr) extends the same two-user Langflow method to FAISS vector namespaces. The reviewed record covers Langflow OSS 1.0.0 through 1.10.1 and states that one user can reuse another user's namespace to read owner-only vector content and persist entries that influence later results.

Use two disposable users and two namespaces containing unique synthetic documents. Establish each owner's search/add baseline, then have user B submit user A's namespace through the exact component/API reached by the target workflow. Test read and write separately: the read proof stops after one synthetic marker appears; the integrity proof inserts one benign `POISON-CANARY` record and then has user A query for that exact marker. Add random, nonexistent, own-namespace, wrong-workspace, and fixed-build controls.

Report **caller-controlled FAISS namespace -> owner binding omitted -> synthetic cross-user vector returned or persisted**. Include user/workspace/flow identity, namespace source, vector-store backend, operation, marker hashes, and post-write cleanup. Never collect real embeddings, prompts, documents, API keys, model output, or another tenant's production namespace.

## July 30 file-route, traversal, and Chroma namespace follow-up

Three additional IBM Langflow records extend the existing file and two-user vector-store workflows:

- [GHSA-c6gg-2q9r-m9jw](https://github.com/advisories/GHSA-c6gg-2q9r-m9jw) describes missing authentication on `/api/v1/files/images/{flow_id}/{file_name}` and insufficient ownership binding on `/api/v1/files/download/{flow_id}/{file_name}`;
- [GHSA-rmxx-p7v6-pmfp](https://github.com/advisories/GHSA-rmxx-p7v6-pmfp) describes URL path traversal using dot-segment variants; and
- [GHSA-vrqm-44rp-59j5](https://github.com/advisories/GHSA-vrqm-44rp-59j5) describes cross-user Chroma reads and writes when a caller reuses another flow's `persist_directory` and `collection_name`.

### File route and path matrix

1. Create users A and B, separate flows, and uniquely named synthetic image/text files. Keep a third temporary sibling directory containing one random canary.
2. Test image and download routes as owner A, non-owner B, anonymous, random flow ID, wrong filename, and administrator. Record whether the server joins `flow_id` and filename back to the authenticated owner.
3. Test canonical path, repeated dot segments, encoded separators, mixed slash forms accepted by the stack, absolute paths, sibling-prefix paths, and a symlink only against the disposable canary root.
4. Capture raw request target, proxy-decoded target, framework route parameters, normalized filesystem path, owner lookup, file-open target, and returned marker.
5. Report unauthenticated route coverage, cross-user object access, and filesystem traversal separately. Never retrieve real uploads, prompts, model artifacts, credentials, or tenant files.

### Chroma two-user namespace matrix

Reuse the FAISS fixture above, but record both `persist_directory` and `collection_name` as authority-bearing selectors. Establish that user B cannot discover user A's namespace through normal list/UI paths; then submit the already known synthetic pair through B's own flow. Prove read and write independently with one random owner marker and one reversible `POISON-CANARY` record. Include mismatched directory/collection pairs, nonexistent values, same-user values, wrong workspace, and fixed-build controls.

Report **caller-controlled Chroma storage pair -> owner binding omitted -> synthetic cross-user vector returned or persisted**. Do not claim arbitrary filesystem access unless the path itself escapes the configured Chroma root and a separate canary proves that edge.

## August 5 provider, MCP, environment, and host-authority follow-up

Nine IBM Langflow OSS records covering 1.0.0 through 1.10.3 extend the same file, outbound-fetch, and MCP-launch methods. Primary IBM bulletins include [node 7282147](https://www.ibm.com/support/pages/node/7282147) and [node 7282650](https://www.ibm.com/support/pages/node/7282650). The GitHub records are [GHSA-fqv5-gx59-2xgv / CVE-2026-9081](https://github.com/advisories/GHSA-fqv5-gx59-2xgv), [GHSA-94h9-q657-456h / CVE-2026-7657](https://github.com/advisories/GHSA-94h9-q657-456h), [GHSA-47c3-vjq8-vj9m / CVE-2026-10128](https://github.com/advisories/GHSA-47c3-vjq8-vj9m), [GHSA-qvrp-rpmf-prw4 / CVE-2026-17625](https://github.com/advisories/GHSA-qvrp-rpmf-prw4), [GHSA-x37c-x545-wrmw / CVE-2026-7646](https://github.com/advisories/GHSA-x37c-x545-wrmw), [GHSA-wq3q-gcx9-xvm2 / CVE-2026-9077](https://github.com/advisories/GHSA-wq3q-gcx9-xvm2), [GHSA-5jpf-5j69-486q / CVE-2026-17630](https://github.com/advisories/GHSA-5jpf-5j69-486q), [GHSA-f93f-mcp7-xm47 / CVE-2026-17626](https://github.com/advisories/GHSA-f93f-mcp7-xm47), and [GHSA-7rx7-4wfr-4qqv / CVE-2026-17623](https://github.com/advisories/GHSA-7rx7-4wfr-4qqv).

Use one isolated Langflow instance with no inherited credentials or unrestricted egress. Replace `requests.get`, MCP resource readers, IDE-config writers, Docker launch, and child-process creation with recorders before supplying canaries.

| Boundary | Fixture | Bounded positive |
| --- | --- | --- |
| provider-key validation to outbound HTTP | owned Ollama-like endpoint, redirects, mapped addresses, rebinding control | accepted `OLLAMA_BASE_URL` selects an owned denied final peer |
| built-in component to process environment | fake `LANGFLOW_CANARY` only; recorder exposes key names, not values | built-in node returns the fake marker despite custom-component restrictions |
| MCP `resources/read` to filesystem | disposable MCP root, encoded path forms, sibling canary | final canonical sibling path reaches denied reader |
| MCP config to IDE files | temporary home/config root and localhost/non-local route matrix | authenticated remote request reaches no-op IDE-config writer despite local-only policy |
| MCP command/config to child process | inert executable plus argv recorder | caller field changes executable or adds shell grammar before launch is denied |
| Docker MCP options to host authority | fake image, temp mount root, volume/device argument matrix | caller option selects an outside-root mount/device at a patched runtime sink |

For provider SSRF, capture validation-time DNS, every redirect, connection-time DNS, and final socket peer; never use metadata or real internal services. For MCP paths, preserve raw, URL-decoded, normalized, and real paths, and distinguish file selection from returned bytes. For process and Docker controls, record argv/runtime configuration without starting a shell, container, or mount. For environment access, expose only a generated fake variable and never inspect inherited values.

Report each edge independently. Do not collapse **MCP config write**, **file read**, **host mount selection**, and **command execution** into one RCE claim unless separate denied-sink evidence proves every transition.

## August 5 second follow-up: validation, cache, memory, and filesystem authority

An adjacent IBM Langflow OSS wave covering 1.0.0 through 1.10.3 adds seven operator-relevant boundaries: [GHSA-994g-w9jv-hxcv / CVE-2026-8182](https://github.com/advisories/GHSA-994g-w9jv-hxcv), [GHSA-x252-wm2h-6mf4 / CVE-2026-8478](https://github.com/advisories/GHSA-x252-wm2h-6mf4), [GHSA-wq52-m42w-xg45 / CVE-2026-9201](https://github.com/advisories/GHSA-wq52-m42w-xg45), [GHSA-4q62-cj5w-qmfx / CVE-2026-9196](https://github.com/advisories/GHSA-4q62-cj5w-qmfx), [GHSA-7xr9-m7x2-5wqq / CVE-2026-7869](https://github.com/advisories/GHSA-7xr9-m7x2-5wqq), [GHSA-vph6-jp7f-x3cx / CVE-2026-9130](https://github.com/advisories/GHSA-vph6-jp7f-x3cx), and [GHSA-f7wm-r5v3-mxr4 / CVE-2026-10547](https://github.com/advisories/GHSA-f7wm-r5v3-mxr4).

| Boundary | Bounded validation target |
| --- | --- |
| unauthenticated two-request path to server-side code handling | Derive both requests from an isolated affected build, replace the interpreter/process sink with a recorder, and prove only that a fixed inert value reaches it. Do not publish an execution payload or test an exposed production instance. |
| caller code to truncated trusted-template digest | Patch the executor, seed one harmless trusted template, and compare full-digest, truncated-digest, non-colliding, and corrected-build decisions. A digest collision accepted by the validator is sufficient; never execute the candidate. |
| LLM-generated component to pre-approval backend validation | Use a deterministic fake model response containing a no-op component and record whether validation reaches filesystem/network/import hooks before approval. Deny those hooks; do not let generated code run. |
| knowledge-base name to filesystem path | Reuse the disposable containment fixture above and target one empty canary directory. Record raw name, normalized path, containment decision, and denied create/write syscall. |
| `session_id` to MemoryComponent history authority | Create two users, flows, and random synthetic sessions; test `/api/v1/run/*`, `/api/v1/responses`, and `/api/v2/workflow/*` with the already known foreign session id. Stop at one marker and never collect real chat history. |
| foreign `flow_id` to shared build-vertex cache | Submit a no-op graph marker through deprecated `POST /api/v1/build/{flow_id}/vertices`, then have the owner read/build only the synthetic flow. Patch cache writes and workflow dispatch so the proof cannot execute or mutate a real flow. |

Treat the sparse traversal record [GHSA-p865-qggm-g9qx / CVE-2026-8183](https://github.com/advisories/GHSA-p865-qggm-g9qx) as a route-discovery seed, not proof that every Langflow path is readable. Preserve the raw request target, proxy decoding, framework route parameters, canonical file target, and denied open call. Use only a lab canary file.

Report the edges separately as **unauthenticated request sequence to denied interpreter sink**, **truncated component digest to trust decision**, **generated component to pre-approval validator**, **knowledge-base name to outside-root denied write**, **session id to foreign synthetic memory**, or **foreign flow id to shared cache entry**. Do not infer universal RCE, arbitrary file access, or cross-user disclosure from an advisory title alone.

## October 5 second follow-up: default-off webhook auth, seedable Fernet vault, and two code-exec sinks ([CVE-2026-8505](https://github.com/advisories/GHSA-cf6m-vc3m-7cgm), [CVE-2026-9205](https://github.com/advisories/GHSA-jxw3-mjmx-3pqm), [CVE-2026-51886](https://github.com/advisories/GHSA-w584-2h2r-2hvf), [CVE-2026-7700](https://github.com/advisories/GHSA-9fpm-3445-2vx4))

A four-leg Langflow wave landed 22:30Z, all durable because each leg is a shipped-default or canonical-shape mistake rather than an exotic bug:

- **Webhook auth is default-off** (CVE-2026-8505, 9.8): `WEBHOOK_AUTH_ENABLE` shipped `False` through 1.9.0, and when false `get_webhook_user` returns the **flow owner** without checking any API key — knowing a flow UUID executes the flow as its owner. Operator rule stands with the shipped-default family: an auth feature whose gate flag defaults off means the feature's *absence-of-config* is the vulnerable state; fingerprint webhook/`/webhook/` routes for owner-context execution with no credential before concluding the deployment is unauthenticated.
- **`random.seed(SECRET_KEY)` derives the credential-vault Fernet key** (CVE-2026-9205, 9.1): all stored user secrets (LLM provider keys, DB passwords) are encrypted with a Mersenne-Twister-derived key; short `SECRET_KEY` values (the common self-hosted case) make the vault key recomputable offline from the seed alone, and long keys use raw key material directly — one file read decrypts everything. Operator rule: when a product derives crypto keys from a config secret, the config read and the DB become one chain, not two findings; test key-derivation shape (seeded PRNG vs stretch vs raw) during any env/config disclosure assessment. Cross-reference the advisory's own note: the MCP path traversal in the same repo is the realistic `SECRET_KEY` source — pair the legs in reports.
- **`exec()` of a "definitions-only" AST still runs decorators** (CVE-2026-51886, 8.8): `/api/v1/validate/code` compiles user `FunctionDef` nodes and execs them to catch syntax errors — decorator expressions evaluate at definition time, so any authenticated user gets RCE. Canonical shape for every "validate/lint/preview my code" endpoint: execution happens at *parse/definition* time via decorators, default values evaluated at def time, and metaclass bodies; a restricted `exec_globals` with standard builtins is not a sandbox.
- **LLM-generated lambda is eval'd with full builtins** (CVE-2026-7700, 8.8): Smart Transform validates the model's output with `startswith("lambda") and ":" in text` then `eval()`s it. Dual-vector: flow author directly, or prompt injection through attacker-controlled content that a deployed flow previews. Rule: any LLM-to-`eval`/`exec`/template sink in a product is reachable by whoever controls the text the flow processes; syntactic format checks are not a validation boundary.

Bounded validation stays per the earlier sections of this page: isolated affected build, flow UUIDs and credentials synthetic, decorator proof an inert marker import, Smart Transform proof a deterministic fake model response with a no-op lambda recorded — never eval against live deployments or decrypt real vault rows.

## October 6 follow-up: unsandboxed interpreter component and never-enforced SSRF guard ([CVE-2026-10561](https://github.com/advisories/GHSA-8qpj-27x8-pwpq), GHSA-j8f7-x8jm-wmm4)

A two-leg Langflow wave landed 13:38Z, both durable because each is a shipped-default/canonical-shape mistake that generalizes across the whole AI-workflow-builder category:

- **`PythonREPLComponent` executes unsandboxed Python; allow-list was decorative** (GHSA-8qpj-27x8-pwpq / CVE-2026-10561, critical 9.9, `langflow < 1.10.1`): the built-in Python Interpreter / Python REPL Tool components passed user- or model-supplied code straight to LangChain `PythonREPL`, which is explicitly not a security sandbox, in-process with service privileges. Two independent weaknesses: (1) `get_globals()` built exec globals from the `global_imports` allow-list but **never set `__builtins__`**, so CPython `exec()` auto-injected the full builtins module — `__import__("os")`, `open`, `eval` reachable regardless of the allow-list, even in the default configuration; (2) components never consulted `allow_custom_components=False` before executing, so even locked-down deployments ran interpreter code. The reported PoC opened a DB session and flipped the caller's own `is_superuser` flag — authenticated-user-to-superuser privesc via direct database access, no auth bug required. Operator rules: **restricted-exec-without-`__builtins__`-key is a canonical shape** — a globals dict lacking the `__builtins__` key gets real builtins injected by CPython, so module allow-lists are cosmetic; grep any sandbox-flavored `exec()`/`eval()` harness for whether `__builtins__` is actually present in its globals. **Policy-flag-to-sink parity**: enumerate every policy flag a product advertises (`allow_custom_components`, block flags) and grep each sensitive component for a reference to it; components added after the flag are routinely ungated — test the flag's *effect* per component, not its existence. **Hardening-series version fingerprinting**: the fix spans 1.10.1 through 1.12.3 as separate layers (safe_builtins, AST dunder/import rejection, fail-closed policy gate, module-proxy blocking `sys.modules` traversal, optional microVM `LANGFLOW_SANDBOX_BACKEND`) — an intermediate version may implement some layers only; fingerprint per layer, per the Airflow grep-every-sibling rule. Cross-reference the same page's July 21 KEV `exec_globals` and October 5 decorator-eval sections: three distinct sinks (validation route, decorators at definition time, interpreter component) in one product — enumerate exec-capable sinks, not fixes.
- **SSRF guard shipped off, warn-only, and unapplied to most URL-taking components** (GHSA-j8f7-x8jm-wmm4, `langflow < 1.10.3`, no CVE): `ssrf_protection.py` existed since 1.7.0 but `ssrf_protection_enabled` defaulted `False`, and its **only caller** (API Request) passed `warn_only=True`, so even enabled it merely logged. RSS Reader, SearXNG, Web Search result-URL fetching, Home Assistant, Glean, and Docling Serve never called the guard at all — any flow-author could fetch loopback, RFC1918, link-local, and `http://169.254.169.254/latest/meta-data/` and read responses through component output. Fix rollout is the operator map: 1.9.3 flipped the default and added DNS-pinned `validate_and_resolve_url()`; 1.10.1 and 1.10.3 routed each remaining component through `ssrf_safe_get`/protected httpx clients per-hop. Durable rules: **guard-helper existence is not enforcement** — grep the guard function name and enumerate every URL-consuming call site that omits it; **`warn_only`-style parameters on security validators are first-class findings** — read call sites and check whether the verdict is ignored; **connector loopback exemptions survive the fix** (documented localhost exemption, `LANGFLOW_CONNECTOR_SSRF_VALIDATION_ENABLED`) so post-patch probes still reach local connector peers while private/metadata ranges block — test both classes; **verify which parameter selects the destination before claiming SSRF**: the advisory itself de-lists the DuckDuckGo/Google-News search legs (hard-coded host, input only into `quote_plus`-encoded path/query) and a client-side SDK helper with no API route — the real sinks were the fetched result URLs.
- Bounded validation unchanged from prior sections: isolated affected build, interpreter proof an inert in-memory marker (no imports of process/filesystem/network helpers), SSRF proof against owned callback servers only — never cloud metadata endpoints or real internal services. Version-fingerprint per hardening layer and per component before crediting a patch level.

Tracked no-publish from this wave: Docling METS-GBS `getmembers()`-before-limit memory exhaustion pair (GHSA-3cr3-8m4c-fpxw / CVE-2026-105747 + duplicate marker GHSA-f4ch-vxwc-3p2m — sibling of the already-tracked f4ch DoS leg, check-after-enumeration class, availability only); `pbkdf2` long-password rehash-per-iteration DoS (CVE-2026-102414, 2013 Django class); sharp→librsvg dependency-relay RCE advisory (GHSA-wq5f-xc86-pv6w / CVE-2026-96889 — relay with no exploit detail; the durable aside that official Node.js binaries are not PIE-compiled is noted here for future desktop/supply-chain pages).

## October 7 03:30Z follow-up: third IBM Langflow wave — range now 1.0.0–1.12.2, and the shipped code-security scanner is itself deny-list-gated

A third IBM Langflow OSS advisory wave (~25 records, published 00:31/03:30Z, covering **1.0.0 through 1.12.2** — the band has grown past the 1.10.1/1.10.3 waves above) lands in the same detail-free IBM summary style: authenticated and unauthenticated remote code execution "due to improper control of code generation" / "improper neutralization of special elements used in an OS command", plus information-disclosure legs. Treat these as route-discovery seeds against the layer-fingerprint already on this page, not as standalone proofs.

- One named class carries a durable axis: **"incomplete blocklist in the code security scanner"** ([GHSA-p2rj-wm8g-5h9f / CVE-2026-97655](https://github.com/advisories/GHSA-p2rj-wm8g-5h9f), high). Langflow ships an *internal* code security scanner whose verdict is a deny-list — meaning the product's own security gate is the bypass surface, and any flow-validation/policy bypass research on this target should probe the scanner's deny-list first (import/attribute/builtin spellings that the AST scanner fails to match, per the page's prior dunder/import-rejection and `sys.modules` proxy layers). This is the product-internal inverse of the external-sandbox legs above: when the *scanner inside the pipeline* is deny-list-gated, every "validated" component still crosses an untrusted parse.
- Operator fingerprint update: three distinct advisory bands (≤1.10.1, ≤1.10.3, ≤1.12.2) in ten weeks means deployed instances cluster by hardening layer, exactly as the page's per-layer fingerprinting rule predicts; banner/version against IBM bulletins remains the first recon step, and the IBM bulletin pipeline (node 7282147/7282650 lineage) is the source-of-truth for route detail the GHSAs omit.
- Tracked without publication from this wave: the remaining summary-only IBM RCE/disclosure/DoS records (wvwm, x724, rc3v, frvf, 3qcv, j57w, 4m6r, j9v6, 43mm, f6p7, xfjh, 4mr4, f4v9, jm65, f976, v6qv, 2cwm, q95g, pc86, g2pv, 75jr and friends) — same-class coverage per the page's standing rule; adjacent NVIDIA Model-Optimizer deserialization (CVE-2026-65142) and TensorRT OOB read (CVE-2026-65122) tracked as model-tooling memory-safety/deserialization class.
