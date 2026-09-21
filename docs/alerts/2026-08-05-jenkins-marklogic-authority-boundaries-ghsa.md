---
title: Jenkins and MarkLogic authority-boundary validation
---

# Jenkins and MarkLogic authority-boundary validation

The August 5 Jenkins and Progress MarkLogic disclosures are useful as two operator workflows rather than a list of versions. Jenkins exposes transitions from weak controller permissions into workspace files, stored credentials, Groovy, or remoting object reconstruction. MarkLogic exposes parser and identity disagreement between a front end, an application server, and SAML, ODBC, REST, or query authorization.

Primary sources: [Jenkins security advisory 2026-08-05](https://www.jenkins.io/security/advisory/2026-08-05/) and [Progress MarkLogic Critical Security Alert Bulletin, August 2026](https://community.progress.com/s/article/Marklogic-Critical-Security-Alert-Bulletin-August-2026). GitHub records are linked below for stable identifiers. Confirm exact affected and fixed versions in those primary bulletins.

!!! warning "Isolated fixtures and patched sinks only"
    Use a disposable Jenkins controller/agent pair, synthetic workspaces and credentials, a local reverse proxy, canary MarkLogic users/documents, and patched file, credential, script, deserialization, query, and session sinks. Never read operational workspaces, capture real credentials, run Groovy or gadget chains, desynchronize shared traffic, impersonate production users, or query production Security data.

## Jenkins: map permission to final authority

Relevant records include:

- controller-side object reconstruction [GHSA-xv7v-hw45-9jgw / CVE-2026-70430](https://github.com/advisories/GHSA-xv7v-hw45-9jgw) and remoting class-filter coverage [GHSA-v269-8r2r-vj93 / CVE-2026-70426](https://github.com/advisories/GHSA-v269-8r2r-vj93);
- symlink and path-classification failures in workspace access [GHSA-xvrr-fjq7-cfrw / CVE-2026-70427](https://github.com/advisories/GHSA-xvrr-fjq7-cfrw) and [GHSA-c232-r242-w9v9 / CVE-2026-70428](https://github.com/advisories/GHSA-c232-r242-w9v9);
- External Workspace Manager authorization drift [GHSA-w8fh-xx7f-5j67 / CVE-2026-70436](https://github.com/advisories/GHSA-w8fh-xx7f-5j67);
- Multijob controller-side Groovy reached through CSRF or unsafe configuration [GHSA-2hx5-662f-6q6f / CVE-2026-70432](https://github.com/advisories/GHSA-2hx5-662f-6q6f) and [GHSA-vxm7-6w3j-gm87 / CVE-2026-70431](https://github.com/advisories/GHSA-vxm7-6w3j-gm87); and
- plugin credential relays such as SCM-Manager [GHSA-h3r9-p4mg-h9jj / CVE-2026-70434](https://github.com/advisories/GHSA-h3r9-p4mg-h9jj), [GHSA-px5p-9c6f-v9v7 / CVE-2026-70435](https://github.com/advisories/GHSA-px5p-9c6f-v9v7), Horreum [GHSA-84xf-jvr9-x4f9 / CVE-2026-70443](https://github.com/advisories/GHSA-84xf-jvr9-x4f9), and Google Chat Notification [GHSA-67r4-vj46-3qpx / CVE-2026-70442](https://github.com/advisories/GHSA-67r4-vj46-3qpx).

### Permission and route matrix

Create anonymous, `Overall/Read`, item-configure, job-owner, agent, and administrator identities. Seed a temporary workspace with one in-root marker, one sibling marker, and a symlink from the workspace to a third canary. Replace file reads with a recorder that stores only canonical path and containment result.

For core and plugin workspace browsers, test list, browse, archive, console-link, and externally managed workspace routes. Capture:

1. raw request path and every decoded form;
2. principal, global permission, item permission, and resolved job;
3. workspace root, selected path, final real path, and symlink resolution; and
4. patched file sink decision.

A bounded positive is **weak principal reaches a workspace route -> target is not bound to an authorized item/root -> final canary path reaches the denied reader**. Route reachability or a path string alone is not file disclosure.

### Stored-credential relay matrix

Seed only fake credentials such as `JENKINS-CANARY-<uuid>`. Replace each plugin connector with an owned no-content recorder that stores destination, credential ID, and a one-way hash of the fake secret.

Vary caller permission, job/folder context, credential scope, credential ID, destination URL, request method, and CSRF crumb. Test credential-ID enumeration separately from credential use. Strong evidence is **caller can select or infer a fake credential outside the job/folder context -> caller controls the connector destination -> recorder receives the canary hash**. A visible credential ID is not proof that the secret can be spent.

### Script and remoting boundaries

- Replace Groovy compilation/execution with an AST recorder. Submit an inert expression that returns a fixed marker and verify whether CSRF or low item permissions can reach a controller-side script sink.
- Replace controller deserialization and remoting class resolution with recorders. Replay only ordinary serialized fixture classes plus one inert class name that should be denied. Record authentication state, transport, declared type, filter decision, class loader, and whether object reconstruction begins.
- Derive Jenkins transport frames from disposable controller/agent traffic and never send gadget chains.

The proof stops at **unauthorized input reaches compiler/object-reconstruction authority after the expected permission or class filter was skipped**. Do not execute a script or instantiate an exploit gadget.

## MarkLogic: separate parser, identity, and object decisions

The Progress cluster includes HTTP request smuggling [GHSA-984c-qj5w-fv7j / CVE-2026-9190](https://github.com/advisories/GHSA-984c-qj5w-fv7j), ODBC authentication bypass [GHSA-j99j-whfx-75gq / CVE-2026-9192](https://github.com/advisories/GHSA-j99j-whfx-75gq), SAML signature verification failure [GHSA-j86w-xf2g-5g65 / CVE-2026-7557](https://github.com/advisories/GHSA-j86w-xf2g-5g65), REST document/query privilege drift [GHSA-8pvj-2hqp-qwfr / CVE-2026-8709](https://github.com/advisories/GHSA-8pvj-2hqp-qwfr), [GHSA-xp9q-9vhj-ggp6 / CVE-2026-7327](https://github.com/advisories/GHSA-xp9q-9vhj-ggp6), and [GHSA-vhc6-v3vv-rx25 / CVE-2026-7329](https://github.com/advisories/GHSA-vhc6-v3vv-rx25), plus low-role SSRF [GHSA-vc8h-qc29-hjr2 / CVE-2026-9203](https://github.com/advisories/GHSA-vc8h-qc29-hjr2).

### HTTP parser differential

Put one local reverse proxy in front of an isolated MarkLogic HTTP App Server. Disable keep-alive reuse by unrelated clients and route the backend only to harmless `/public-canary` and `/auth-canary` handlers. Send one connection at a time and compare:

- one valid `Content-Length` request;
- one valid chunked request;
- duplicate and conflicting framing controls; and
- the exact affected-versus-fixed `Content-Length` plus `Transfer-Encoding` fixture derived from the primary bulletin or patch.

Record raw bytes, proxy message boundaries, backend message boundaries, connection reuse, selected route, and authentication context. A positive is a boundary mismatch that makes the canary route execute under a different request context. Do not target another user's connection, cache, or session.

### Identity proof matrices

Use two canary users, one low-role user, one synthetic administrator identity, a local SAML IdP, and a patched query dispatcher.

| Surface | Vary | Required proof |
| --- | --- | --- |
| ODBC | known/unknown username, correct/incorrect canary password, low/admin identity | password verification decision and resolved principal diverge before a no-op query sink |
| SAML | valid signed assertion, modified assertion, missing/alternate signature location, wrong audience/recipient | unsigned or incorrectly signed claims resolve a canary principal before session issuance is denied |
| REST patch/query | low-role document, operation, database, query language, target object | low role reaches a Security or privileged-operation sink without the required privilege |

Never issue a real privileged query. Patch session issuance and query dispatch so the strongest result is a tuple containing resolved canary principal, requested operation, target database, and denied decision.

### Final-peer SSRF evidence

Use an owned redirector and two owned listeners: one public validation address and one synthetic denied peer. Record raw URL, normalized host, DNS answers, redirect chain, selected socket peer, caller role, and patched response sink. Test only representations supported by the exact affected connector.

A bounded positive is **low-role request passes URL policy -> transport selects the owned denied peer -> response recorder sees only a random canary hash**. Do not probe metadata, RFC1918 services, or production internal hosts.

## Reporting

- Name the exact transition: `Overall/Read -> foreign workspace reader`, `item configuration -> stored credential connector`, `CSRF -> controller Groovy`, `remoting frame -> disallowed object reconstruction`, `front-end frame -> backend request boundary`, `unsigned SAML claims -> canary principal`, or `low REST role -> privileged query sink`.
- Include affected and fixed builds, enabled plugin/App Server, caller role, route/transport, canonical path or raw bytes, final sink, and negative controls.
- Keep unreviewed GitHub records as discovery seeds. Version and behavior claims should cite the Jenkins or Progress bulletin and an affected-versus-fixed lab result.

## September 21 follow-up: Groovy sandbox escape via annotation member values the whitelist never parses (GHSA-3xcj-rvrm-wg64)

[GHSA-3xcj-rvrm-wg64](https://github.com/advisories/GHSA-3xcj-rvrm-wg64) / CVE-2026-92126 (CVSS 8.5): Jenkins Script Security ≤ `1415.v9a_f9b_3a_c253d` rejects blacklisted annotations and members but **does not reject `@Builder` annotations whose `builderStrategy` member names an arbitrary class** — a sandboxed script author (anyone who can define a Pipeline) reaches code outside the sandbox if a suitable class is on the evaluating component's classpath.

- Durable axis for every script-sandbox you assess: **the whitelist inspects the syntax tree at the level the author typed, not at the level the runtime resolves.** Annotation member values, string indirections (`Class.forName`-style), reflection entry points, and code-generation hooks (Lombok `builderStrategy`, `@GroovyASTTransformationClass`, service-loader files) are resolution-time class names the static checker never parses. Enumerate every annotation/attribute whose member is a *class name* in the evaluated language and test whether the sandbox rejects it.
- Jenkins-specific check: from a sandboxed Pipeline, attempt an inert marker annotation carrying a benign class reference and record whether Script Security rejects at compile time; escalate only in an isolated lab controller with a purpose-built harmless gadget class, never production controllers or real credential classes.
- Sibling pattern already on this page (remoting class-filter coverage) and on the Sept 17/19 JS and Python sandbox pages: **guard coverage = parser coverage** — a denylist over surface syntax misses any path where the *resolver* picks the executable object.
