# Agent, deploy, SSRF, and identity boundary checks

Source: hourly offensive-security scan, 2026-07-07 late GitHub advisory wave. Primary entries: [GHSA-r6vm-4xwg-w69h](https://github.com/advisories/GHSA-r6vm-4xwg-w69h), [GHSA-698x-9w2p-7vvp](https://github.com/advisories/GHSA-698x-9w2p-7vvp), [GHSA-vmfc-9982-2m45](https://github.com/advisories/GHSA-vmfc-9982-2m45), [GHSA-2jcc-mxv7-p3f9](https://github.com/advisories/GHSA-2jcc-mxv7-p3f9), [GHSA-6w3m-4hhp-775q](https://github.com/advisories/GHSA-6w3m-4hhp-775q), [GHSA-f66q-9rf6-8795](https://github.com/advisories/GHSA-f66q-9rf6-8795), [GHSA-4g5x-hcwm-82jw](https://github.com/advisories/GHSA-4g5x-hcwm-82jw), [GHSA-26rh-24rg-j3vv](https://github.com/advisories/GHSA-26rh-24rg-j3vv), [GHSA-q855-8rh5-jfgq](https://github.com/advisories/GHSA-q855-8rh5-jfgq), [GHSA-v3q9-hj7j-63hq](https://github.com/advisories/GHSA-v3q9-hj7j-63hq), [GHSA-m3cr-vc2j-pm27](https://github.com/advisories/GHSA-m3cr-vc2j-pm27), and [GHSA-qrpv-q767-xqq2](https://github.com/advisories/GHSA-qrpv-q767-xqq2).

This batch is durable because the advisories repeat operator-relevant boundaries: session identifiers crossing into agent authorization, manifest and VCS URLs crossing into server-side fetchers, OpenAPI `$ref` and proxy bypass paths ignoring a declared deny policy, tenant scaler metadata crossing into connection-string keys, reauthentication proofs crossing users, deployment manager IDs crossing namespaces, MCP add-on routes escaping their secret path, email addresses crossing into protocol command framing, workspace deep links crossing into shell-backed dotfiles setup, and flow IDs crossing tenant ownership.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-r6vm-4xwg-w69h](https://github.com/advisories/GHSA-r6vm-4xwg-w69h) / CVE-2026-10212 | AstrBot `astr_main_agent` | caller-shaped `session_id` changes agent authorization context | Add session-ID tampering to chatbot/agent route tests; prove only with disposable conversations and synthetic tool outputs. |
| [GHSA-698x-9w2p-7vvp](https://github.com/advisories/GHSA-698x-9w2p-7vvp) / CVE-2026-10517 | Claircore manifest layer fetcher | unauthenticated manifest descriptors can contain server-fetched URLs when PSK is absent | Test registry/scanner ingest paths as SSRF clients using owned callbacks and non-sensitive lab responses. |
| [GHSA-vmfc-9982-2m45](https://github.com/advisories/GHSA-vmfc-9982-2m45) / CVE-2026-50127 | Weblate VCS URL restrictions | private-address guard missed transitional IPv6, multicast, and semi-private ranges | Reuse URL canonicalization matrices for VCS import/fetch features, including IPv6 transition and unusual private ranges. |
| [GHSA-2jcc-mxv7-p3f9](https://github.com/advisories/GHSA-2jcc-mxv7-p3f9) / CVE-2026-53508 | `oasdiff` git-revision loader | `--allow-external-refs=false` was not enforced for `rev:path` OpenAPI specs | Test every loader path for the same `$ref` policy; prove with canary HTTP refs and disposable local files. |
| [GHSA-6w3m-4hhp-775q](https://github.com/advisories/GHSA-6w3m-4hhp-775q) / CVE-2026-53572 | KEDA PostgreSQL scaler | tenant-controllable scaler fields can inject libpq parameters through non-space whitespace | Add tab/newline/form-feed separators to connection-string injection harnesses for Kubernetes autoscaler CRDs. |
| [GHSA-f66q-9rf6-8795](https://github.com/advisories/GHSA-f66q-9rf6-8795) | Flask-Security-Too WebAuthn reauth | any owned WebAuthn credential could refresh another currently authenticated user's freshness gate | Test reauth proof binding to the current session subject, not only credential validity. |
| [GHSA-4g5x-hcwm-82jw](https://github.com/advisories/GHSA-4g5x-hcwm-82jw) / CVE-2026-53553 | Goploy `/deploy/fileDiff` | client-supplied compare paths can escape the intended project/remote-file boundary | Validate deployment diff/read APIs with marker files, never secrets or production config. |
| [GHSA-26rh-24rg-j3vv](https://github.com/advisories/GHSA-26rh-24rg-j3vv) / CVE-2026-53552 | Goploy project and project-file handlers | JSON body row IDs are not namespace-bound before file and git remote operations | Use two namespaces to test cross-project IDOR and keep RCE proof to inert git-remote/argv markers. |
| [GHSA-q855-8rh5-jfgq](https://github.com/advisories/GHSA-q855-8rh5-jfgq) | `ha-mcp` Home Assistant add-on | settings and backup routes are also mounted at bare root without secret-path auth | Check MCP/add-on UIs for duplicate route mounts that bypass secret paths, ingress assumptions, Origin checks, or CSRF controls. |
| [GHSA-v3q9-hj7j-63hq](https://github.com/advisories/GHSA-v3q9-hj7j-63hq) / CVE-2026-53533 | `aiosmtplib` sender/recipient APIs | CRLF in email addresses crosses into additional SMTP command lines | Add protocol-framing tests for mail libraries that accept user-controlled envelope fields. |
| [GHSA-m3cr-vc2j-pm27](https://github.com/advisories/GHSA-m3cr-vc2j-pm27) | Coder workspace auto-create and dotfiles module | deep-link parameters can trigger shell-backed dotfiles setup without explicit user consent | Treat developer-platform deep links as provisioning authority; prove with disposable workspaces and inert dotfile markers. This is an adjacent follow-up to the existing Coder workspace/repository boundary page. |
| [GHSA-qrpv-q767-xqq2](https://github.com/advisories/GHSA-qrpv-q767-xqq2) | Langflow `/api/v1/responses` | authenticated users can execute another user's flow by supplying a foreign flow UUID | Continue two-user flow-IDOR tests for monitor/response/build APIs using synthetic prompts and marker outputs only. This is an adjacent follow-up to the existing Langflow monitor/API boundary page. |

## Replayable validation boundaries

### URL, manifest, and spec-loader SSRF

- Build a lab instance with a harmless HTTP callback service under your control.
- For scanner or registry ingest paths, submit manifests, layer descriptors, repository URLs, VCS import URLs, or OpenAPI `$ref`s that point only to the callback service.
- Include canonicalization variants: `localhost`, loopback IPv4, IPv4-mapped IPv6, transitional IPv6, multicast, link-local, trailing dots, mixed case, userinfo, and owned DNS-rebinding names.
- Positive evidence is a callback or reflected canary response from a representation the target policy meant to block.
- Do not target cloud metadata, internal admin panels, service discovery, or production private networks.

### Policy consistency across loader paths

- For tools with multiple input modes, exercise each loader independently: local file, remote URL, git working tree, `rev:path`, API upload, and CI integration if present.
- Apply the same explicit deny policy, such as `--allow-external-refs=false`, to each mode.
- Positive evidence is a blocked external reference in one loader path that is fetched or read in another.
- Keep local-file proofs to disposable canary files under a temporary directory; never read credentials, SSH keys, cloud config, notebooks, or source outside the authorized test fixture.

### Agent, MCP, and developer-platform authorization

- Use disposable agent profiles, Home Assistant add-ons, Coder deployments, and Langflow users.
- Test whether route context is bound to the same subject across `session_id`, flow ID, workspace auto-create parameters, secret paths, and bare-root duplicate mounts.
- For MCP/add-on settings, only read route metadata or toggle inert test settings. Do not restore/delete real backups, run tools against live devices, or mutate production assistants.
- For Coder dotfiles or similar provisioning modules, use inert marker commands or a fake dotfiles repository that writes only inside the disposable workspace.
- For Langflow response execution, create two users and two synthetic flows; positive evidence is execution or output from User A's flow when authenticated as User B.

### Identity freshness and protocol command framing

- For WebAuthn reauthentication, register separate disposable users and credentials. Submit User A's WebAuthn assertion while User B's session is at a reauth gate.
- Positive evidence is only the freshness-state transition on the wrong session subject; do not perform protected state changes beyond a harmless canary endpoint.
- For SMTP clients, pass CRLF-bearing sender/recipient canaries to a mock SMTP server and capture the raw command transcript.
- Positive evidence is additional SMTP command lines framed from an address string. Do not send mail to third parties, authenticate to production relays, or inject destructive SMTP verbs.

### Deployment and scaler tenant-boundary tests

- In Goploy-like deployment managers, create two namespaces/projects and use marker files only. Attempt foreign project/file row IDs in read, write, delete, and git-remote update handlers.
- Stop at evidence of cross-namespace read/write authority or command argument construction; do not deploy, overwrite source, or touch production remotes.
- In KEDA-like scaler tests, create a disposable `ScaledObject` and mock PostgreSQL endpoint. Inject tabs, newlines, carriage returns, and form feeds into tenant-controlled `host`, `dbName`, `userName`, `port`, and `sslmode` fields.
- Positive evidence is an extra libpq key/value observed by the mock endpoint or connection log, not live database access.

## Reporting notes

- Name the exact crossed boundary: **agent session ID to authorization context**, **manifest URL to server fetch**, **git-revision spec to ignored external-ref deny**, **tenant scaler field to libpq key injection**, **foreign WebAuthn credential to current-session freshness**, **body row ID to cross-namespace deployment action**, **secret-path MCP UI to bare-root route**, **email address to SMTP command line**, **deep link to workspace command execution**, or **foreign flow ID to response execution**.
- Include version, route, role, plugin/add-on mode, exact loader path, raw URL/address form, canonical host/address, route-mount evidence, mock-server transcript, and negative controls from patched or properly bound paths.
- Keep all artifacts synthetic: disposable users, canary flows, temporary workspaces, fake projects, marker files, mock SMTP/PostgreSQL services, owned callback domains, and redacted token prefixes only.
