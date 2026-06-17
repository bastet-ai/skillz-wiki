# Gitea, LangChain4j, HAPI FHIR, agent WebFetch, and WebSocket boundary checks

Source: hourly offensive-security scan, 2026-06-17. Primary entries: GitHub advisories [GHSA-fhx7-m96w-mv29](https://github.com/advisories/GHSA-fhx7-m96w-mv29) / CVE-2026-22555, [GHSA-wrr5-99h5-gq57](https://github.com/advisories/GHSA-wrr5-99h5-gq57) / CVE-2026-24791, [GHSA-9cpj-qc93-vw8v](https://github.com/advisories/GHSA-9cpj-qc93-vw8v) / CVE-2026-28737, [GHSA-2mfg-cc43-9pcj](https://github.com/advisories/GHSA-2mfg-cc43-9pcj) / CVE-2026-55405, [GHSA-2f55-g35j-5jmf](https://github.com/advisories/GHSA-2f55-g35j-5jmf) / CVE-2026-55471, [GHSA-8fq9-273g-6mrg](https://github.com/advisories/GHSA-8fq9-273g-6mrg) / CVE-2026-55518, [GHSA-r4gv-qr8j-p3pg](https://github.com/advisories/GHSA-r4gv-qr8j-p3pg) / CVE-2026-55760, [GHSA-fg94-h982-f3mm](https://github.com/advisories/GHSA-fg94-h982-f3mm) / CVE-2026-54316, [GHSA-8788-j68r-3cgh](https://github.com/advisories/GHSA-8788-j68r-3cgh) / CVE-2026-54022, [GHSA-qwxf-2m7m-2m3x](https://github.com/advisories/GHSA-qwxf-2m7m-2m3x) / CVE-2026-54324, and [GHSA-mx8g-39q3-5c79](https://github.com/advisories/GHSA-mx8g-39q3-5c79) / CVE-2026-9595.

This batch is durable because each item exposes a reusable operator boundary: API-only authorization checks that diverge from UI controls, public-only token flags that are not enforced on self-route families, repository file previewers that turn file metadata into trusted DOM, vector-store metadata filters that concatenate SQL identifiers and literals, XML transform helpers that bypass a project's hardened factory, admin UI association writes that skip attach-policy checks, template loaders that trust user-controlled template names, agent WebFetch allowlists that bless attacker-controlled paths under a pre-approved host, Socket.IO document ids that normalize after authorization checks, tenant WebSocket joins keyed by client-supplied organization ids, and dev-server WebSocket proxies that accidentally forward privileged browser headers to user proxies.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-fhx7-m96w-mv29 / CVE-2026-22555 | Gitea API forks | `POST /api/v1/repos/{owner}/{repo}/forks` checked organization membership but not `CanCreateOrgRepo()` before creating an org fork | Test self-hosted Git for API/UI authorization drift where repository creation unlocks Actions, deploy keys, or organization secret exposure. |
| GHSA-wrr5-99h5-gq57 / CVE-2026-24791 | Gitea public-only tokens | `/api/v1/user/...` self routes accepted tokens marked `public-only` without the private-resource restriction enforced by canonical user routes | Validate OAuth/token scope flags route-family by route-family, not just on the obvious resource endpoint. |
| GHSA-9cpj-qc93-vw8v / CVE-2026-28737 | Gitea 3D file viewer | unsupported glTF `extensionsRequired` values crossed into an Online3DViewer error rendered with `innerHTML` | Probe repository previewers where attacker-controlled file metadata, parser errors, or model/viewer diagnostics render under the forge origin. |
| GHSA-2mfg-cc43-9pcj / CVE-2026-55405 | LangChain4j MariaDB / pgvector stores | embedding metadata filter keys and some values were concatenated into SQL | Test AI/RAG search filters as SQL construction inputs, especially JSON-key, column-per-key, and `removeAll(Filter)` paths. |
| GHSA-2f55-g35j-5jmf / CVE-2026-55471 | HAPI FHIR utilities | `saxonTransform(...)` instantiated a bare Saxon `TransformerFactoryImpl` instead of the project's XXE-protected factory | Search for alternate XML helper families that bypass a central hardened parser/transformer wrapper. |
| GHSA-8fq9-273g-6mrg / CVE-2026-55518 | Avo admin UI | the association attach form checked `attach_<association>?`, but the write endpoint did not | Replay hidden/disabled admin UI actions directly against mutation endpoints when associations represent tenants, teams, roles, or ownership. |
| GHSA-r4gv-qr8j-p3pg / CVE-2026-55760 | handlebars.java | `FileTemplateLoader` / `ClassPathTemplateLoader` could compile user-selected template names outside the intended root | Validate template-name parameters against canonical template roots with traversal and classpath controls. |
| GHSA-fg94-h982-f3mm / CVE-2026-54316 | Claude Code WebFetch | a pre-approved bare hostname (`huggingface.co`) implicitly trusted attacker-controlled repository paths for agent-initiated fetches | Treat agent URL allowlists as origin-plus-path policy; test whether approved public hosts can be used as controlled out-of-band canary channels. |
| GHSA-8788-j68r-3cgh / CVE-2026-54022 | Open WebUI Socket.IO notes | authorization ran only for `note:<id>`, while storage normalized `:` to `_`, letting `note_<id>` reach the same Yjs document | Test real-time collaboration document ids for auth-before-normalization mismatches. |
| GHSA-qwxf-2m7m-2m3x / CVE-2026-54324 | Daytona notification WebSocket | the JWT-authenticated gateway joined a client-supplied `organizationId` room without verifying membership | Validate tenant-scoped WebSocket subscriptions with canary org ids and passive event sinks. |
| GHSA-mx8g-39q3-5c79 / CVE-2026-9595 | webpack-dev-server | broad proxy contexts with `ws: true` could intercept the dev server's HMR WebSocket and forward cookies / `Origin` to the proxy target | Include developer-tooling proxies in recon when localhost/dev origins carry privileged cookies or OAuth sessions. |

## Operator triage

1. **Prioritize boundary reuse over product names.** The strongest targets are self-hosted Git forges with API/UI drift, RAG/vector integrations with user-controlled metadata filters, healthcare/FHIR or XML-heavy tools that maintain multiple parser helper families, admin back offices with relationship-management endpoints, agent runtimes with pre-approved outbound hosts, and collaboration/WebSocket gateways with tenant or document-room joins.
2. **Confirm the exact preconditions.** Gitea fork impact depends on organization membership plus disabled org-repo creation and enabled Actions/secret inheritance. Gitea glTF requires a file preview sink. LangChain4j requires attacker-controlled metadata keys or filters entering MariaDB/pgvector stores. HAPI FHIR requires a caller that applies `saxonTransform(...)` to attacker-influenced XML, DTD, or stylesheet material. Claude Code requires untrusted context injection into a vulnerable agent session.
3. **Use canaries only.** Prove with disposable orgs, repositories, roles, vector rows, XML callbacks, template roots, WebFetch URLs, notes, organization ids, and dev-server proxy targets. Do not exfiltrate live CI secrets, private notes, patient records, repository tokens, account cookies, or environment variables.
4. **Collect negative controls.** Each report should include an unaffected route, patched version, denied policy check, rejected template path, safe parser wrapper, blocked WebSocket room, or scoped proxy configuration to prove the crossed boundary is specific.

## Replayable validation boundaries

### Gitea API fork to organization-secret boundary

- Build a disposable Gitea organization with one read-only member in a team where repository creation is disabled.
- Seed only a synthetic organization Action secret such as `SKILLZ_CANARY_SECRET`, never real credentials.
- Confirm the web UI blocks creating/forking into the organization, then call the fork API as the same user against an approved test repository.
- Positive proof is creation of an org-scoped fork and admin rights over that fork despite the UI/policy restriction. If Actions inheritance is in scope, use a workflow that prints only whether the synthetic canary exists, not its value.
- Evidence: version, team settings, API request/response, resulting fork ownership/permissions, and fixed-build denial.

### Gitea public-only token route-family validation

- Create a test account with one public-only token or OAuth grant scoped only for the approved route family.
- Compare canonical private-resource routes with `/api/v1/user/...` self routes that expose or mutate private account material such as SSH keys, emails, tokens, or settings.
- Positive proof is a route-family mismatch: the canonical route rejects the public-only token while a self route returns or changes the synthetic private canary.
- Do not enumerate production keys, emails, repositories, or settings. Use a disposable account and marker values.

### Repository previewer metadata-to-DOM validation

- Use a non-production repository and upload a harmless `.gltf` canary that places a visible marker in `extensionsRequired` or equivalent parser-error metadata.
- Visit the file preview as a test user and observe whether the marker is inserted as HTML rather than text.
- Stop at a local marker such as a DOM attribute or text change. Do not create payloads that steal tokens, create API keys, or modify repositories.
- Evidence: viewer version, canary file, rendered error fragment, DOM sink, and patched escaping behavior.

### LangChain4j metadata-filter SQL boundary

- In a lab app, seed a MariaDB or pgvector embedding store with synthetic rows and metadata keys.
- Route only a benign time-delay or boolean canary through `EmbeddingSearchRequest.filter()` or `removeAll(Filter)`. Keep the query scoped to a disposable table/index.
- Positive proof is a measurable SQL behavior caused by the metadata key or value that cannot occur when identifiers/literals are parameterized or allowlisted.
- Do not extract real vectors, documents, prompts, tenant ids, API keys, or database metadata.

### HAPI FHIR Saxon XXE boundary

- Identify whether the application calls `XsltUtilities.saxonTransform(...)`; do not assume every HAPI FHIR deployment is exposed.
- Use a controlled XML document and a canary DTD/URL on infrastructure you own. Prefer a single blind callback proof or a synthetic local marker in a lab container.
- Positive proof is that the Saxon transform path resolves an external entity while the hardened `transform(...)` path does not.
- Never read patient data, server config, credentials, cloud metadata, or internal service endpoints.

### Avo association attach authorization drift

- Create a low-privileged Avo user and two synthetic records where attaching the association would imply tenant, team, role, ownership, or project access.
- Confirm the UI/form route hides or denies the attach action, then submit the direct association `POST` mutation with the same user.
- Positive proof is a relationship change that violates the configured `attach_<association>?` policy.
- Evidence should include only synthetic record ids/names and before/after relationship state.

### handlebars.java template-loader traversal

- Confirm that user input can select a template name and that a `FileTemplateLoader` or `ClassPathTemplateLoader` is active.
- Place a harmless marker file outside the intended template root in a lab filesystem.
- Submit traversal-shaped template names and record whether the marker renders or errors disclose path reachability.
- Stop at a disposable marker. Do not read `/etc`, home directories, application secrets, classpath credentials, or production templates.

### Agent WebFetch approved-host canary channel

- In a lab Claude Code session on an affected version, introduce untrusted content that asks the agent to fetch a canary path under an approved public host you control, such as a repository file path with a marker in the URL.
- The proof is an outbound request that happens without the expected permission/tooling gate because the bare host is pre-approved.
- Encode only a fixed canary. Do not encode environment variables, command output, source files, tokens, or user data.
- Evidence: agent version, allowlist behavior, untrusted prompt fragment, requested URL, and fixed-version prompt/tool denial.

### Socket.IO document-id normalization boundary

- Use two disposable users and a canary note/document in an Open WebUI lab instance.
- As the unauthorized user, attempt to join both the canonical `note:<id>` room and the normalized-looking `note_<id>` room.
- Positive proof is denial on the canonical id but receipt of canary Yjs state through the alternate id.
- Capture only synthetic note content and room ids; do not target real user notes or chats.

### Tenant notification WebSocket join validation

- Create two test organizations and one low-privileged user that belongs to only one of them.
- Connect to the notification WebSocket with the user's JWT while supplying the other organization's id, then trigger a harmless event in the other org.
- Positive proof is receipt of the other org's canary event without membership.
- Do not subscribe to production tenant rooms or collect runner, sandbox, volume, or user activity events.

### webpack-dev-server HMR WebSocket proxy boundary

- Reproduce only in a local/dev environment. Configure a broad proxy context such as `/` with `ws: true` and a controlled proxy target.
- Open the dev app with a synthetic cookie and observe whether the HMR WebSocket handshake reaches the proxy target with browser headers.
- Positive proof is a canary cookie or `Origin` reaching the proxy target when it should have remained on the dev-server HMR channel.
- Do not test on shared developer machines with real sessions.

## Reporting heuristics

- Title reports around the crossed boundary: **API fork bypass to org secret exposure**, **public-only token self-route bypass**, **viewer parser error to trusted DOM**, **metadata key to SQL**, **alternate XML helper to XXE**, **association attach policy drift**, **template name to filesystem read**, **approved agent host to OOB fetch**, **document-id normalization auth bypass**, **client-supplied org WebSocket join**, or **HMR WebSocket proxy interception**.
- Keep impact bounded by proof. Avoid claiming full account takeover, org compromise, patient-data exposure, or secret theft unless the synthetic canary demonstrates the same path and the owner approved that scope.
- Include the vulnerable and safe comparator: UI denied vs API accepted, canonical route denied vs self route allowed, hardened XML helper vs Saxon helper, `note:` denied vs `note_` joined, or narrow proxy path vs broad `ws` proxy.
- Redact tokens, repository names, org ids, room ids, runner logs, and paths when they identify a customer environment. Synthetic canaries are sufficient.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger research, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. CakePHP and Gitea redirect backslash bypasses, Filament disabled RichEditor XSS, Langflow unauthenticated upload resource exhaustion/path disclosure, Multer/Deno/HAPI ReDoS, Capsule namespace finalize access-control drift, Keycloak identity-first enumeration, and generic memory/resource issues were tracked but not promoted in this page because the batch above provides higher-signal replayable authorization, parser, SQL, WebSocket, filesystem, and agent-boundary workflows. CISA added Joomla Content Editor, LiteSpeed cPanel symlink, and Cisco SD-WAN Manager path traversal KEVs; they were recorded for state, but the public offensive guidance should wait for stronger primary technical detail or a non-duplicative boundary beyond existing cPanel/SD-WAN filesystem notes.
