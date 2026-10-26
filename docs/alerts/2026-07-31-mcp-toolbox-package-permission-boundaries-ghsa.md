---
title: MCP Toolbox, package argument, and Node permission boundaries
---

# MCP Toolbox, package argument, and Node permission boundaries

A July 31 advisory wave yields six reusable operator checks: an MCP OAuth verifier can accept tokens minted for an unrelated audience; a legacy HTTP route can omit tool scopes; dataset policy can fail open on an empty dry-run result; redirect following can move an approved HTTP tool to a different authority; a package name can become an `apt-get` option; and a diagnostic report API can write beyond a runtime filesystem policy.

Sources:

- [Google MCP Toolbox GHSA-656w-qf75-c5gf / CVE-2026-14541](https://github.com/advisories/GHSA-656w-qf75-c5gf): the record describes Google OAuth access tokens being accepted without audience validation when `mcpEnabled: true` is combined with no explicit `audience` or `clientId`;
- [Google MCP Toolbox GHSA-f8h2-c55w-8m5p / CVE-2026-14537](https://github.com/advisories/GHSA-f8h2-c55w-8m5p): the record says legacy direct-HTTP invocation routes bypassed `scopeRequired` when `--enable-api` was active in versions 1.3.0 and 1.4.0;
- [Google MCP Toolbox GHSA-24pp-m59v-92j8 / CVE-2026-14538](https://github.com/advisories/GHSA-24pp-m59v-92j8): the record reports fail-open `allowedDatasets` validation when a BigQuery dry run returned an empty reference array for specialized query forms;
- [Google MCP Toolbox GHSA-3x3x-8ffg-ghcv / CVE-2026-14540](https://github.com/advisories/GHSA-3x3x-8ffg-ghcv): the record reports missing redirect and destination-IP controls in generic HTTP sources and tools through 1.4.0;
- [yggdrasil-worker-package-manager GHSA-f9rr-qg3x-wq4m / CVE-2026-18157](https://github.com/advisories/GHSA-f9rr-qg3x-wq4m): the record describes hyphen-prefixed package names being interpreted as `apt-get` options; and
- [Node.js GHSA-4qw5-6jhx-9hfx / CVE-2026-58039](https://github.com/advisories/GHSA-4qw5-6jhx-9hfx): the record says `process.report` could overwrite files outside paths granted by `--allow-fs-write` in affected 22.x, 24.x, and 26.x releases.

These were unreviewed GitHub Advisory Database records at scan time. Treat versions and claimed behavior as source leads. Reproduce the exact artifact and configuration, identify the reachable sink, and compare against a fixed release before reporting.

!!! warning "Recorder-only labs"
    Use fake OAuth tokens, disposable MCP tools, a mocked BigQuery client, two owned HTTP listeners, an argument-recording package backend, and a temporary Node filesystem. Never replay real Google tokens, query production datasets, follow redirects toward internal services, install attacker-selected packages, overwrite shell or service configuration, or read files through a write-only proof.

## Boundary matrix

| Surface | Attacker-controlled value | Authority transition | Bounded positive |
| --- | --- | --- | --- |
| MCP OAuth | otherwise valid token with a foreign `aud` | token validity becomes toolbox authorization | foreign-audience canary reaches one no-op tool while a correct-audience control also succeeds |
| Direct HTTP API | route family and tool name | legacy handler invokes a scoped MCP tool | missing-scope user reaches a marker-only tool only through the legacy route |
| BigQuery policy | specialized query form | empty dry-run references become policy approval | denied synthetic dataset is selected by a recorder despite an allowlist |
| Generic HTTP tool | path/URL input and redirect target | approved initial authority becomes final request authority | owned listener A redirects to owned listener B and B receives the canary |
| Package manager | hyphen-prefixed package token | package data becomes `apt-get` option grammar | recorder shows the token parsed as an option without running `apt-get` |
| Node permission model | report filename/path | diagnostic report writer bypasses filesystem grant | report marker appears in a disposable denied sibling directory |

Keep each edge separate. Token acceptance is not data access until a protected tool runs. A route returning `200` is not a scope bypass without the missing-scope control. An empty dry-run result is not dataset access until the execution sink receives the query. A redirect response is not SSRF until the final owned listener is contacted. A suspicious package string is not command execution unless option parsing changes. A report-path bypass is a write-policy finding, not arbitrary file read.

## MCP OAuth audience-confusion differential

### Preconditions

- exact MCP Toolbox build under test;
- Google `authService` with `mcpEnabled: true`;
- one recorder-only protected tool;
- two disposable OAuth clients or a local verifier fixture that can mint signed canary claims; and
- authorization to test the identity configuration.

### Procedure

1. Record whether `audience` or `clientId` is explicit in the auth-service configuration.
2. Mint three non-sensitive canaries: valid issuer/signature plus expected audience, valid issuer/signature plus foreign audience, and invalid signature plus expected audience.
3. Submit each token through the same MCP transport and tool call.
4. Record token-verification outcome separately from tool invocation.
5. Repeat after setting an explicit expected audience and, where available, against a fixed build.

| Token | Signature/issuer | Audience | Expected secure result |
| --- | --- | --- | --- |
| positive control | valid | expected toolbox client | no-op tool allowed |
| audience probe | valid | unrelated owned client | rejected before tool dispatch |
| signature control | invalid | expected toolbox client | rejected before tool dispatch |

A useful finding requires the foreign-audience token to cross the protected dispatch boundary. Do not report merely that an access token can be parsed.

## Route-family scope coverage

Build a route-by-auth matrix for the same tool:

| Route family | No token | Valid token, missing scope | Valid token, required scope |
| --- | --- | --- | --- |
| MCP transport | reject | reject | invoke marker |
| legacy API with `--enable-api` | reject | reject | invoke marker |
| API disabled | unavailable | unavailable | unavailable |

Capture handler identity, authorization middleware reached, status, and recorder count. The positive is a missing-scope principal incrementing the tool recorder only through the legacy route. This distinguishes policy drift from harmless status-code differences.

## BigQuery dry-run fail-open testing

Use a mocked BigQuery adapter or a throwaway project containing only `allowed_lab.marker` and `denied_lab.marker`.

1. Configure `allowedDatasets` to include only `allowed_lab`.
2. Establish controls: a direct allowed-table query is accepted and a direct denied-table query is rejected.
3. Feed the validator specialized query classes one at a time, including `INFORMATION_SCHEMA` references and a mocked federated-query construct.
4. Instrument the dry-run result and execution call. Force or observe an empty referenced-table array without contacting a real external connection.
5. The bounded positive is execution receiving a query that names `denied_lab` after the validator treated an empty reference set as approval.
6. On a fixed control, an empty or indeterminate reference set must fail closed unless an independent parser proves every referenced dataset is allowed.

Do not extract schema or row data. A recorder containing the synthetic denied dataset name is sufficient evidence.

## Redirect final-destination proof

Use two isolated owned listeners:

```text
listener A: approved initial authority; replies 302 to listener B
listener B: distinct owned authority; records method, path, and inert header names
```

Test direct input and redirect input separately. Vary only one boundary at a time: hostname, resolved address class, port, or scheme. Preserve the complete redirect chain and prove which request attributes are forwarded. Do not target metadata, loopback services belonging to other software, private production ranges, or third-party endpoints.

The report should state whether policy was applied to the initial URL, every redirect hop, and the final resolved destination. An open redirect on listener A alone is not evidence that Toolbox followed it.

## Package token to option grammar

Replace the APT backend with an argument recorder or intercept the child-process constructor before execution.

1. Submit a normal synthetic package name and preserve the resulting argv array.
2. Submit a hyphen-prefixed inert token such as `--skillz-canary`.
3. Confirm whether the backend inserts `--` before untrusted package operands.
4. Compare raw argv with the option parser's interpretation; do not infer parsing from the source string alone.
5. The positive is a package operand occupying option position or changing parsed option state. Stop before package installation or any option that reads configuration, runs hooks, changes roots, or selects a network source.

A fixed control should reject invalid package grammar and use an end-of-options delimiter where supported.

## Node diagnostic-report write confinement

Run the affected Node build in a temporary tree:

```text
/tmp/node-perm-lab/
├── allowed/
└── denied/marker-target
```

Grant writes only to `allowed/`, invoke the reachable `process.report` write API with a path under `denied/`, and check only whether a random report marker file was created or replaced. Use a dedicated process and disposable files. Repeat with ordinary `fs.writeFile` as the denied control and with a fixed Node release.

Capture the exact Node version, permission flags, requested path, canonical path, pre/post hashes of the disposable target, and exit status. Do not target startup files, package manifests, service units, credentials, or application data.

## October 26 follow-up: MCP Toolbox cloud-storage source — unauthenticated path traversal exfiltrates host files to attacker GCS buckets (CVE-2026-93328 / [GHSA-2gc9-c85v-5vwr](https://github.com/advisories/GHSA-2gc9-c85v-5vwr), versions 1.2.0–1.4.0)

Fourth independent advisory family on this product (after the July 31 OAuth/route/policy legs and the June/July protocol-version + host-allowlist legs). The `cloud-storage` tool source combines path traversal with missing authorization: an **unauthenticated** remote attacker crafts tool-invocation parameters to (a) exfiltrate host files by uploading them to an **external Google Cloud Storage bucket the attacker names**, and (b) overwrite arbitrary local files.

Operator axes:

- **Cloud-SDK-backed tool sources are file-exfiltration primitives with a built-in upload leg.** The exfil destination does not need an outbound HTTP channel — an attacker-supplied bucket name rides the platform's own authorized GCS client. When auditing any MCP/agent tool that wraps a cloud storage SDK, test bucket/container/object parameters for attacker-controlled destination values, not just source-path traversal.
- **Tool-source parity sweep again**: the OAuth layer, the legacy HTTP route family, the protocol-version handlers, and now the cloud-storage source each failed independently on the same binary. Enumerate every registered tool source separately — auth middleware correctness says nothing about per-source parameter handling (this page's standing adapter-parity rule, validated a fifth time).
- Probe shape on an authorized lab Toolbox: a disposable instance with one cloud-storage tool, a synthetic local marker file, and a bucket you own; a traversal-shaped source parameter landing the marker in your bucket is the bounded positive. Never touch real buckets or host files outside a disposable root.

## Evidence and reporting

For each finding preserve:

- exact package/runtime version and configuration;
- attacker prerequisite and transport/route used;
- raw token claims, argv, redirect chain, query-validator result, or canonical path with secrets removed;
- the guard decision and the separate sink-side recorder event;
- positive, negative, and fixed-version controls; and
- the narrowest demonstrated impact.

Prefer boundary-specific titles such as “legacy API omits required tool scope” or “diagnostic report writer escapes permission-model write grant.” Do not collapse the six workflows into generic “MCP RCE,” “SSRF,” or “sandbox escape” claims.