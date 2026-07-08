---
title: Integration, deployment, and MCP boundary checks from July 8 GHSA wave
---

# Integration, deployment, and MCP boundary checks from July 8 GHSA wave

This batch turns a July 8 GitHub Advisory wave into replayable validation ideas for authorized pentests and bug-bounty work. The common thread is parser or route state that operators trusted to constrain an integration boundary, but which did not apply on every input path.

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

!!! warning "Authorized validation only"
    Keep every proof in a lab or customer-approved environment. Use canary URLs, marker files, fake SMTP servers, disposable clusters, and inert project repositories. Do not read secrets, redirect live production integrations, alter real deployment remotes, or approve dangerous MCP actions.

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
- LLM agents, RAG tools, or developer assistants that expose LangChain filesystem search, prompt loaders, or chain/agent config loaders to untrusted prompts, shared repositories, or tenant workspaces.

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

## Reporting notes

A strong report for this wave should include:

- the exact input path that bypassed the expected guard, such as git-revision loading versus file loading;
- a normalization table for URL, host, cluster, namespace, or connection-string parsing;
- the minimum role or tenant permission required;
- marker-only evidence from owned callbacks, fake listeners, temp files, disposable namespaces, mocked clusters, certificate AIA callbacks, or agent-workspace canaries;
- clear negative controls showing the intended blocked path still blocks when the parser variant is not used.
