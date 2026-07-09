---
title: Integration, deployment, agent, CMS, and MCP boundary checks from July 8 GHSA wave
---

# Integration, deployment, agent, CMS, and MCP boundary checks from July 8 GHSA wave

This batch turns a July 8 GitHub Advisory wave into replayable validation ideas for authorized pentests and bug-bounty work. The common thread is parser, browser, route, or filesystem state that operators trusted to constrain an integration boundary, but which did not apply on every input path.

Sources:

- [GHSA-vmfc-9982-2m45: Weblate SSRF private-range bypass](https://github.com/advisories/GHSA-vmfc-9982-2m45)
- [GHSA-2jcc-mxv7-p3f9: oasdiff git-revision external `$ref` bypass](https://github.com/advisories/GHSA-2jcc-mxv7-p3f9)
- [GHSA-6w3m-4hhp-775q: KEDA PostgreSQL connection-string parameter injection](https://github.com/advisories/GHSA-6w3m-4hhp-775q)
- [GHSA-f66q-9rf6-8795: Flask-Security-Too WebAuthn freshness bypass](https://github.com/advisories/GHSA-f66q-9rf6-8795)
- [GHSA-4g5x-hcwm-82jw: Goploy file-diff path traversal](https://github.com/advisories/GHSA-4g5x-hcwm-82jw)
- [GHSA-26rh-24rg-j3vv: Goploy cross-namespace project/file IDOR and git-remote RCE primitive](https://github.com/advisories/GHSA-26rh-24rg-j3vv)
- [GHSA-q855-8rh5-jfgq: ha-mcp unauthenticated add-on settings routes](https://github.com/advisories/GHSA-q855-8rh5-jfgq)
- [GHSA-v3q9-hj7j-63hq: aiosmtplib SMTP CRLF command injection](https://github.com/advisories/GHSA-v3q9-hj7j-63hq)
- [GHSA-gvhc-wv3v-7pf8: Kite cluster overview RBAC bypass](https://github.com/advisories/GHSA-gvhc-wv3v-7pf8)
- [GHSA-m557-wrgg-6rp4: phpseclib X.509 AIA certificate-validation SSRF](https://github.com/advisories/GHSA-m557-wrgg-6rp4)
- [GHSA-gr75-jv2w-4656: LangChain file-search and loader path traversal](https://github.com/advisories/GHSA-gr75-jv2w-4656)
- [GHSA-5j6p-jrrm-6x94: Apache Airflow KubernetesExecutor Execution API JWT exposed in worker pod command-line arguments](https://github.com/advisories/GHSA-5j6p-jrrm-6x94)
- [GHSA-vr7m-c6v4-8cx8: Apache Airflow FAB / Keycloak logout paths leave API JWTs valid until expiry](https://github.com/advisories/GHSA-vr7m-c6v4-8cx8)
- [GHSA-37h2-6p4f-mp3q: Serena fixed-port unauthenticated Flask dashboard DNS-rebinding to agent memory/RCE](https://github.com/advisories/GHSA-37h2-6p4f-mp3q)
- [GHSA-xqhv-chqm-fhcc: Joro wildcard-CORS local API plugin upload RCE](https://github.com/advisories/GHSA-xqhv-chqm-fhcc)
- [GHSA-v5px-423j-pf7p: Nuclio cron trigger headers/body shell-command injection](https://github.com/advisories/GHSA-v5px-423j-pf7p)
- [GHSA-9x82-rm84-c6x7: DSpace LDN Velocity template RCE chain](https://github.com/advisories/GHSA-9x82-rm84-c6x7)
- [GHSA-9qm4-rh6w-pq5x: DSpace LDN template path traversal](https://github.com/advisories/GHSA-9qm4-rh6w-pq5x)
- [GHSA-c827-pw3m-67w7: DSpace ORE resource URI scheme validation gap](https://github.com/advisories/GHSA-c827-pw3m-67w7)
- [GHSA-v66x-68f2-pxf5: DSpace curation reporter output path traversal](https://github.com/advisories/GHSA-v66x-68f2-pxf5)
- [GHSA-35rm-7j9c-2f7m: async-tar PAX extension-header desync and entry/content smuggling](https://github.com/advisories/GHSA-35rm-7j9c-2f7m)
- [GHSA-wf93-45jw-7689: pip entry-point script path traversal](https://github.com/advisories/GHSA-wf93-45jw-7689)
- [GHSA-rmxx-v9rj-vpvg: Casdoor local filesystem storage provider arbitrary file write](https://github.com/advisories/GHSA-rmxx-v9rj-vpvg)
- [GHSA-75w3-gmqx-993q: Waku cross-origin CSRF on RSC server action dispatch](https://github.com/advisories/GHSA-75w3-gmqx-993q)
- [GHSA-43fc-v873-qw85: Waku `unstable_redirect()` open redirect](https://github.com/advisories/GHSA-43fc-v873-qw85)
- [GHSA-659f-rgp5-w4wf: Skipper OPA request-body authorization bypass on chunked / HTTP/2 requests](https://github.com/advisories/GHSA-659f-rgp5-w4wf)
- [GHSA-4jhm-jv67-739f: `lxml_html_clean.Cleaner` namespaced URL attribute sanitizer bypass](https://github.com/advisories/GHSA-4jhm-jv67-739f)
- [GHSA-6h3c-r723-7fx3: NL Portal task IDOR and tampering](https://github.com/advisories/GHSA-6h3c-r723-7fx3)
- [GHSA-qpm9-h556-mwxm: NL Portal GraphQL document and decision IDOR](https://github.com/advisories/GHSA-qpm9-h556-mwxm)
- [GHSA-vmwx-m75v-qvch: Sharp Quick Creation Command missing authorization](https://github.com/advisories/GHSA-vmwx-m75v-qvch)

!!! warning "Authorized validation only"
    Keep every proof in a lab or customer-approved environment. Use canary URLs, marker files, fake SMTP servers, disposable clusters, inert project repositories, throwaway browser profiles, and synthetic portal records. Do not read secrets, redirect live production integrations, alter real deployment remotes, upload executable plugins, poison real agent memories, submit another user's real forms, or approve dangerous MCP actions.

## Operator use

Use this page when a scope includes:

- translation/localization platforms that fetch repositories or remote VCS URLs;
- OpenAPI diff or review pipelines that claim to disable external `$ref` resolution;
- Kubernetes event-driven autoscaling where tenants can submit `ScaledObject` or `TriggerAuthentication` metadata;
- Flask apps that rely on WebAuthn reauthentication freshness for sensitive actions;
- self-hosted deployment dashboards with project namespaces and remote server inventories;
- Home Assistant MCP add-ons or other MCP tools exposed through trusted-LAN assumptions;
- Python mail integrations that pass user-influenced envelope addresses into `sendmail()`-style APIs;
- multi-cluster Kubernetes dashboards that select a target cluster from headers, query strings, or cookies;
- certificate-enrollment, SAML, mTLS, webhook-signature, or document-signing flows that parse caller-supplied X.509 certificates server-side;
- LLM agents, RAG tools, or developer assistants that expose LangChain filesystem search, prompt loaders, or chain/agent config loaders to untrusted prompts, shared repositories, or tenant workspaces;
- Apache Airflow deployments where the `KubernetesExecutor`, `FabAuthManager`, or `KeycloakAuthManager` joins Kubernetes read permissions, worker pod specs, and Execution API authorization;
- local developer/agent dashboards that listen on predictable loopback ports and trust browser same-origin policy, CORS, Host headers, or DNS stability as their only boundary;
- serverless or platform controllers where tenant-supplied trigger metadata is rendered into Kubernetes Jobs, CronJobs, shell wrappers, or generated config;
- repository, archive, package-manager, CMS, or identity platforms that turn user-controlled path names, entry-point names, URI schemes, templates, storage providers, or object IDs into file reads/writes or privileged records;
- React Server Components / server-action frameworks where cross-origin forms or safelisted content types can reach state-changing server actions.
- Waku apps that pass callback, return, or `next` parameters to `unstable_redirect()` after login, invite, checkout, or OAuth-like flows.
- Skipper reverse proxies where `opaAuthorizeRequestWithBody` policies are expected to deny or allow requests based on JSON/body fields.
- HTML sanitization pipelines using `lxml_html_clean.Cleaner` or legacy `lxml.html.clean` with `safe_attrs_only=False` but still relying on JavaScript URL-scheme stripping.

## Recon checklist

| Boundary | What to look for | Safe canary |
| --- | --- | --- |
| Outbound URL filters | Transitional IPv6 ranges, multicast, semi-private IPv4 ranges, IPv4-mapped IPv6, and hostname aliases not covered by the allowlist/denylist | Owned callback host and a synthetic internal canary service approved for the test |
| OpenAPI `$ref` loading | Separate file, URL, git-revision, GitHub Action, and library load paths with different external-ref settings | `$ref` to an owned callback and a disposable local marker file in a temp workspace |
| Libpq-style connection strings | Tenant fields concatenated as `key=value` with only literal spaces escaped | Mock PostgreSQL listener and fake credentials |
| WebAuthn freshness | Reauthentication route verifies a credential but does not bind the proven credential owner to the current session user | Two disposable users with separate WebAuthn credentials |
| Deployment namespaces | Body-supplied project IDs, file IDs, server IDs, namespace headers, or git remote URLs accepted without server-side ownership checks | Two disposable namespaces/projects and inert repository URLs |
| MCP settings routes | Settings, policy, approval, backup, restart, or tool-visibility endpoints mounted both under a secret path and at a bare root path | Route/status matrix and inert policy toggles in a lab add-on |
| SMTP envelope APIs | Sender/recipient values copied into SMTP commands without rejecting `\r` or `\n` | Local fake SMTP server and a benign marker command sequence |
| Cluster dashboards | `x-cluster-name`, query, or cookie target selection before RBAC middleware | Two disposable clusters or mocked clientsets with aggregate-only canaries |
| Certificate-chain fetching | X.509 AIA `caIssuers` URLs fetched during validation of an untrusted certificate | Owned HTTP callback and an approved synthetic internal canary, never metadata endpoints |
| Agent file tools | Glob patterns, prompt/config path fields, symlinks, or path-prefix checks that are validated before canonicalization | Temp workspace with in-root and sibling marker files plus symlink canaries |
| Airflow orchestration tokens | Worker pod command-line args expose Execution API JWTs, or UI logout does not revoke API JWTs for FAB / Keycloak auth managers | Disposable Airflow namespace, fake DAG/Variable markers, and redacted token-prefix evidence |
| Browser-to-loopback agent APIs | Fixed local ports, wildcard CORS, missing Host/Origin checks, unauthenticated dashboard routes, memory-write APIs, plugin upload APIs, and restart endpoints | Disposable browser profile plus inert memory/plugin markers; never live shell payloads |
| Serverless trigger rendering | Cron trigger headers, bodies, environment fields, or labels concatenated into `/bin/sh -c`, `curl`, or generated Kubernetes specs | Lab namespace and marker-only command arguments captured from generated manifests |
| CMS/repository file boundaries | Template paths, ORE/LDN resource URIs, curation output paths, local storage roots, or package entry-point names escaping intended directories | Synthetic templates, marker files, and disposable package wheels/sdists |
| Archive parser differentials | PAX, GNU longname/longlink, symlink, or extension headers parsed differently by scanners and extraction libraries | Offline tar fixtures and extraction into temp directories only |
| Cross-origin server actions | `text/plain` or `multipart/form-data` POSTs reaching state-changing server actions without `Origin` / `Sec-Fetch-Site` checks | Harmless server-action marker and owned attacker page in a lab app |
| Redirect helpers | User-controlled return/callback/next values reflected into `Location` headers without path-only enforcement | Owned redirector domain and a same-site benign path control |
| OPA body gates | Proxy authorization policy reads `input.parsed_body`, but chunked HTTP/1.1 or HTTP/2 requests reach upstream with a body the policy did not parse | Lab Skipper route, mock upstream, and a harmless denied-field canary |
| Namespaced sanitizer attributes | Sanitizer URL rewriting only visits ordinary `href` / `src` attributes while SVG `xlink:href` or other namespaced URL attributes survive | Offline render fixture with a non-executing marker URL and DOM diff |
| Portal/API object IDs | Task IDs, document IDs, decision IDs, entity IDs, or quick-create command IDs accepted without per-user or per-entity authorization | Two disposable users and synthetic records with unique canary fields |

## Validation patterns

### Weblate and URL guard canonicalization

1. Confirm the target actually enables a private-network restriction such as Weblate `VCS_RESTRICT_PRIVATE`.
2. Build a decision table for representative forms: regular public hostname, loopback, RFC1918, link-local, IPv4-mapped IPv6, transitional IPv6, multicast, and decimal/octal/hex IPv4 aliases.
3. Point only to owned callback infrastructure unless the program explicitly provides an internal canary endpoint.
4. Evidence should show the submitted URL form, the server-side canonical form if visible, and whether the callback fired.

Do not probe arbitrary internal addresses. The finding is strongest when you show one normalization form that bypasses a policy which blocks its equivalent canonical address.

### oasdiff git-revision `$ref` path

The advisory is specifically about the `rev:path` input form, not every oasdiff load path.

1. Create a disposable repository with an OpenAPI document containing one external `$ref` to an owned callback, for example `https://canary.example.test/schema.json`.
2. Run the same policy through the file path and git-revision path:

```bash
oasdiff diff ./openapi.yaml ./openapi.yaml --allow-external-refs=false
oasdiff diff main:openapi.yaml HEAD:openapi.yaml --allow-external-refs=false
```

3. Capture whether the file path blocks the external reference while the git-revision path resolves it.
4. For local-file tests, use only a temp marker file created for the assessment.

### KEDA PostgreSQL scaler parameter injection

Focus on string-to-wire behavior, not credential theft.

1. Stand up a disposable PostgreSQL-compatible listener you control.
2. Submit a `ScaledObject` or `TriggerAuthentication` in a lab namespace where tenant metadata is allowed.
3. Place non-space whitespace such as a tab between injected libpq parameters in a tenant-controlled field, for example a fake `dbName` or `host` value that appends `host=<owned-listener>`.
4. Evidence should be limited to the listener receiving a connection attempt with fake credentials or to KEDA logs showing the parsed target.

Never redirect production KEDA credentials or downgrade live database TLS as a proof.

### Flask-Security-Too WebAuthn freshness

This is a cross-user credential-binding test.

1. Create two disposable accounts, each with its own WebAuthn credential.
2. Put user A's session into a state where a sensitive action requires fresh reauthentication.
3. Attempt to complete the WebAuthn reauthentication challenge using user B's credential.
4. A vulnerable app marks user A's session fresh even though the assertion proved user B's credential.

Report the precondition clearly: you still need a way to drive requests inside the victim session, such as an existing same-origin gadget, CSRF against cookie-authenticated endpoints, session fixation, or direct test control of the lab browser.

### Goploy namespace, file, and git-remote boundaries

Keep Goploy proofs marker-only.

1. Create two namespaces with separate projects and a low-privilege or manager-role user in only one namespace.
2. Enumerate whether body-supplied `projectId`, `projectFileId`, `id`, `serverId`, or namespace headers select objects outside the caller's namespace.
3. For file-read checks, create synthetic canary files on the Goploy host and on a disposable managed server; do not target `/etc/passwd`, SSH keys, deployment secrets, or application config.
4. For write/RCE-adjacent checks, use a fake git remote URL or wrapper repository that logs argv and creates an inert marker. Do not deploy or execute payloads on production servers.

Useful evidence is a before/after namespace matrix: caller namespace, requested object namespace, expected authorization result, actual result, and marker-only impact.

### ha-mcp add-on root route exposure

1. Identify whether the installation is the Home Assistant add-on mode with port `9583` published.
2. Compare route behavior under the secret path and at the bare root path.
3. Test only low-impact endpoints first, such as reading tool visibility or feature flags.
4. If policy routes are enabled, use an inert policy marker and show whether unauthenticated requests can read or modify it.

Do not invoke real high-risk tools, restore backups, delete backups, or restart shared add-ons unless the assessment scope explicitly permits that action.

### aiosmtplib SMTP command framing

1. Use a local fake SMTP server that records raw command lines.
2. Exercise the application's exact mail path: direct `SMTP.mail()`/`rcpt()`, `sendmail()`, or higher-level wrappers that pass envelope addresses through.
3. Submit sender or recipient canaries containing CRLF plus a harmless SMTP verb, such as a second `RCPT TO:<marker@example.test>`.
4. Evidence should be a raw transcript from the fake server proving the injected bytes became a separate command line.

Do not use third-party SMTP servers, real recipients, or authentication commands in proofs.

### Kite cluster selector RBAC

1. Configure or request a test deployment with at least two clusters and a user authorized for only one.
2. Send the overview request with `x-cluster-name` set to the unauthorized cluster.
3. Capture whether aggregate node, pod, namespace, service, CPU, or memory data is returned instead of `403`.
4. Keep evidence aggregate-only; do not request pod names, secret data, kubeconfigs, or bearer tokens.

### phpseclib X.509 AIA certificate-validation SSRF

This is a certificate-content-to-outbound-fetch boundary. The interesting target is not a generic URL input; it is a server path that accepts a certificate and then calls phpseclib `X509::validateSignature()` or equivalent chain validation on that untrusted certificate.

1. Identify certificate ingestion points: SAML metadata/cert upload, mTLS client-certificate enrollment, webhook signing keys, PDF/document-signature validation, package-signing portals, or admin import workflows.
2. In a lab, generate a disposable certificate whose Authority Information Access `caIssuers` URI points at an owned callback host.
3. Submit the certificate through the same application path that performs server-side validation.
4. Capture only callback metadata proving the validator fetched the AIA URI: timestamp, method, path, source network, and a unique assessment token.
5. If the program explicitly provides an internal canary service, repeat with that canary to show policy bypass. Do not target cloud metadata IPs, loopback admin panels, or arbitrary private addresses.

Useful negative controls: a certificate with no AIA URI, a certificate where the issuer is already trusted locally, and a blocked ordinary URL-fetch feature in the same app. The report should make clear that the outbound request was triggered by certificate validation, not by a user-visible URL field.

### LangChain filesystem-search and loader containment

Treat LangChain file tools as agent sandbox boundaries: prompts, repository files, or retrieved content can influence path selection even when the application intended to expose only one workspace root.

1. Build a disposable workspace with:
   - `workspace/allowed.txt` as the expected readable file;
   - `workspace-link -> ../outside-marker.txt` as a symlink canary, when the platform permits symlinks;
   - `workspace-sibling/outside-marker.txt` to catch string-prefix checks such as `/tmp/work` allowing `/tmp/work-sibling`.
2. Exercise each exposed path separately: file-search middleware start directory, search pattern/glob, prompt loader path fields, chain/agent configuration loader paths, and any path-prefix authorization helper.
3. Submit canary patterns that should remain in-root, then patterns or config values that try to resolve through `..`, symlinks, absolute paths, or prefix-sibling names.
4. Evidence should be a table of requested value, resolved path if observable, expected allow/deny, actual result, and whether only the synthetic marker was returned.

Do not aim the proof at `/etc/passwd`, cloud credentials, notebooks, model weights, SSH keys, or customer files. The strongest bug-bounty report shows one positive in-root read, one blocked control, and one bypass that returns a disposable marker outside the intended root.

### Apache Airflow KubernetesExecutor and logout token boundaries

These advisories are useful when a target treats Airflow as an internal workflow control plane but also grants users read-only Kubernetes visibility or long-lived browser/API sessions. The bug-hunting question is whether a token minted for one Airflow trust context remains usable from another context.

#### KubernetesExecutor worker pod command-line leakage

1. Confirm the deployment uses Apache Airflow with `KubernetesExecutor` and that the test account has authorized `pods/get` or equivalent read-only access in the Airflow namespace.
2. Trigger or wait for a disposable DAG task that creates a worker pod. Use a DAG, Variable, Connection, and XCom set created only for the assessment.
3. Inspect the worker pod spec or `kubectl describe pod` output for an Execution API JWT passed as a command-line argument.
4. If the program permits active validation, replay only against harmless Execution API operations tied to the disposable DAG, such as reading a synthetic Variable or attempting a marker-only state transition.
5. Evidence should redact the token to a short prefix/suffix and show the authority boundary: Kubernetes read permission -> token visibility -> Airflow API action.

Do not harvest production task tokens, Connections, Variables, XComs, or DAG outputs. A strong report does not need secret disclosure; it needs a minimal proof that pod-spec read access becomes Airflow API authority.

#### FAB / Keycloak logout residual API token validity

1. Confirm the Airflow auth manager is `FabAuthManager` or `KeycloakAuthManager`; SimpleAuthManager is not the reported affected path.
2. In a lab or disposable user session, capture a short-lived API JWT through the normal authenticated UI/API flow.
3. Click logout in the UI and then retry one low-impact authenticated API request with the same JWT before natural expiry.
4. Compare expected behavior (`401` or revoked token) with actual behavior (token still accepted until expiry).

Frame this as session-boundary drift, not as a request for longer token lifetimes. Keep proof requests read-only or marker-only and avoid clearing real DAG runs or touching production workflow state.

### Serena and Joro browser-to-loopback control planes

Treat loopback agent and developer dashboards as browser-reachable attack surfaces. The reusable bug-hunting pattern is a trusted local API exposed to any page the operator visits.

1. Fingerprint whether the tool starts a local dashboard automatically and whether the port is fixed or predictable. For Serena, the advisory identifies TCP `24282`; for Joro proxy mode, the advisory identifies `127.0.0.1:9090`.
2. From an owned test page in a disposable browser profile, attempt only low-impact probes first: route existence, `Host` handling, `Origin` handling, CORS policy, and whether safelisted content types avoid preflight.
3. For memory-write paths, use a harmless marker such as `SKILLZ_CANARY_DO_NOT_EXECUTE` and verify only that the marker appears in the intended lab memory store.
4. For plugin upload or restart paths, stop at route reachability and request acceptance unless the lab explicitly permits inert plugin loading. If a plugin proof is necessary, use a plugin that writes a temp marker file and performs no network or shell action.

Evidence should show: local service version/mode, browser origin, request content type, CORS/Host/Origin decision, accepted route, and marker-only effect. Do not run shell commands through the agent, modify real project memories, upload production plugins, or rely on secret exfiltration as proof.

### Nuclio cron trigger command construction

This is a controller-to-Kubernetes command-boundary check. The advisory describes tenant-controlled cron trigger `event.headers` keys and `event.body` values entering a generated `/bin/sh -c` `curl` command.

1. Work in a disposable Nuclio namespace with a canary function and no production credentials.
2. Submit two cron-trigger variants:
   - a safe control with ordinary headers/body;
   - a marker variant containing shell metacharacters in a header key or command-substitution-looking text in the body.
3. Inspect the generated CronJob manifest or controller-rendered args before execution when possible.
4. If execution is authorized in a lab, make the marker write only to a disposable temp path inside the test container or send only to an owned callback.

Do not publish working destructive command payloads. The useful operator evidence is the string-to-manifest diff showing that untrusted trigger metadata crossed into shell syntax.

### DSpace LDN, ORE, and curation file/template chains

The DSpace advisories are admin- or collection-admin-reachable boundaries, not unauthenticated bugs. They are still useful in assessments where delegated repository administrators can configure harvesting, LDN, or curation features.

1. Create a lab DSpace collection with a disposable Collection/Community/Site Administrator.
2. For ORE URI scheme checks, configure only a controlled OAI/ORE source that references a synthetic local marker or owned web resource. Do not use `/etc/passwd` or application config.
3. For LDN template path traversal, use a synthetic template outside the intended `$dspace.dir/config/ldn` directory whose content is a fixed harmless Velocity marker.
4. For Velocity execution checks, stop at proving that an unintended template is parsed and evaluated with a benign marker expression. Do not run Java reflection payloads in shared systems.
5. For curation reporter paths, write only to a lab temp directory or static marker path expressly created for the test.

Report the minimum delegated role required, the configured feature path, the intended base directory or URI scheme policy, and the marker-only read/write/render result.

### async-tar parser differential fixtures

Use this when an ingestion pipeline scans tar files with one parser but extracts with Rust `async-tar` or a service built on it.

1. Build an offline fixture corpus with simple tar entries, PAX `x` headers, GNU longname `L` headers, and the reported `x -> L -> file` ordering.
2. Compare file listings and extracted hashes between the production-equivalent extractor and a reference parser such as GNU tar in isolated temp directories.
3. Keep payloads inert: text files with unique marker bytes, not scripts, symlinks to real paths, or executables.
4. Evidence should be a table of parser, visible entry list, extracted path, extracted hash, and whether the validator and extractor disagree.

The finding is strongest when a scanner says one harmless file exists but the actual extractor writes a different marker file or content blob.

### pip and Casdoor filesystem write boundaries

These are path-to-write checks. For pip, the path comes from `console_scripts` / `gui_scripts` entry-point names. For Casdoor, it comes from Local File System storage provider paths available to an authenticated administrator.

1. Use disposable sandboxes only: an isolated virtualenv for pip and a throwaway Casdoor instance with a fake storage provider.
2. For pip, create a synthetic package whose entry-point name attempts to escape the target script directory and write a marker script path under a temp parent directory.
3. Install with explicit target/prefix options inside the sandbox and capture the resolved script path. Do not target shell startup files, real PATH directories, or user dotfiles.
4. For Casdoor, configure a lab local-storage provider and attempt to write only `casdoor-canary.txt` under an approved temp directory outside the nominal storage root.
5. Record expected root, submitted path, canonical resolved path, and marker presence.

### Waku server-action CSRF and redirect helpers

For React Server Components and server-action frameworks, test whether browser-safelisted cross-origin requests can invoke state changes with victim cookies. Also check whether redirect helpers enforce the documented path-only contract before writing the `Location` header.

1. Build or request a lab route with a harmless `'use server'` action that increments a canary counter or stores a marker string.
2. From an owned cross-origin page, send `POST` requests with `Content-Type: text/plain` and a plain HTML form using `multipart/form-data`.
3. Include controls with absent, foreign, and `Origin: null` contexts such as sandboxed iframes when scope permits.
4. For redirect paths, identify callback-style parameters passed to `unstable_redirect()`, then compare a same-site path such as `/account/canary`, an absolute external URL, and a scheme-relative URL such as `//owned.example.test/canary`.
5. Capture response status, whether the canary action executed, and the exact `Location` header for redirect cases.

Do not test against account, payment, admin, or content-destruction server actions in production. For redirects, use only owned domains and do not collect real OAuth codes, session tokens, or credentials. The report should tie the impact to whatever action or redirect flow the target app exposes, not to Waku generically.

### Skipper OPA request-body authorization bypass

This is a proxy/parser differential: the policy engine may evaluate an empty body while the upstream receives the full chunked or HTTP/2 payload.

1. Confirm the route uses Skipper with `opaAuthorizeRequestWithBody` and a Rego rule that reads `input.parsed_body` or body-derived fields.
2. Build a mock upstream or lab route that records only synthetic marker fields.
3. Send three controls: fixed `Content-Length` JSON with an allowed marker, fixed `Content-Length` JSON with a denied marker, and the same denied marker over HTTP/1.1 `Transfer-Encoding: chunked` or HTTP/2 without an explicit content length.
4. Evidence should show the OPA decision, response status, upstream receipt, protocol/framing variant, and the marker field value.

Keep proofs to lab routes or explicit customer-approved canaries. Do not use this to bypass production business controls, submit real forbidden content, or reach private upstream actions outside the assessment scope.

### `lxml_html_clean` namespaced URL-attribute sanitizer bypass

Use this when a target sanitizes user-controlled rich HTML/SVG and then renders it back as trusted content.

1. Confirm the sanitizer stack: `lxml_html_clean.Cleaner` or legacy `lxml.html.clean`, whether `safe_attrs_only=False` is enabled, and whether SVG or namespaced attributes are preserved.
2. Build an offline fixture containing a harmless ordinary `href` control and a namespaced URL attribute such as SVG `xlink:href` with a clearly marked non-production URL.
3. Compare sanitizer output: ordinary JavaScript-style URLs should be stripped or rewritten; the bug is that namespaced URL attributes can survive the same URL-scheme check.
4. If browser validation is in scope, use a local static page and a non-credentialed disposable browser profile. Stop at DOM/output evidence or a click on an owned marker URL; do not attempt credential theft or persistent payloads.

Report the sanitizer configuration, raw input, sanitized output, and rendering context. This is strongest when the application explicitly promised URL-scheme sanitization while allowing rich SVG or lenient attributes.

### NL Portal and Sharp authorization drift

These are object-ownership and entity-permission checks for authenticated low-privilege users.

1. Create two disposable portal users with separate tasks, documents, decisions, or Sharp entity permissions.
2. Capture each user's authorized object IDs from normal UI/API flows.
3. Replay only marker updates or read requests by substituting user B's object ID into user A's task, document, decision, or Quick Creation Command request.
4. Evidence should show expected `403`/empty result versus actual read, form submission, record creation, or returned object fields.

Never use real citizen, customer, or production form data as proof. Seed synthetic records with clear canary values and redact tokens/cookies from screenshots.

## Reporting notes

A strong report for this wave should include:

- the exact input path that bypassed the expected guard, such as git-revision loading versus file loading;
- a normalization table for URL, host, cluster, namespace, or connection-string parsing;
- the minimum role or tenant permission required;
- marker-only evidence from owned callbacks, fake listeners, temp files, disposable namespaces, mocked clusters, certificate AIA callbacks, or agent-workspace canaries;
- for Airflow, a role matrix showing Kubernetes namespace read permissions, Airflow role, auth manager/executor mode, redacted token exposure or residual validity, and marker-only API impact;
- for browser-to-loopback bugs, the exact browser origin, local port, route, content type, CORS/Host/Origin behavior, and inert marker effect;
- for redirect, proxy-body, and sanitizer bypasses, a control-vs-bypass table showing same-site path versus external `Location`, fixed-length versus chunked/HTTP2 body parsing, or ordinary versus namespaced URL attributes;
- for package/archive/filesystem bugs, a canonical path or parser-differential table rather than a sensitive file read;
- for IDOR and authorization drift, a two-user object matrix with synthetic canaries only;
- clear negative controls showing the intended blocked path still blocks when the parser variant is not used.
