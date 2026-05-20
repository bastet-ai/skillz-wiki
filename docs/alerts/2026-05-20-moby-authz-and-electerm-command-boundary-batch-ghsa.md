# Moby AuthZ and electerm command-boundary batch

Source: GitHub Security Advisories, updated 2026-05-20:
[GHSA-x744-4wpc-v9h2 / CVE-2026-34040](https://github.com/advisories/GHSA-x744-4wpc-v9h2) and
[GHSA-x73w-g8hx-v7rp / CVE-2020-23256](https://github.com/advisories/GHSA-x73w-g8hx-v7rp).

This batch is durable for operators because both issues sit at authorization-to-execution seams: a Docker daemon can let a body-sensitive AuthZ policy decide without the body it expects, and a terminal client service accepted unverified requests that reached command execution.

## What changed

- **Moby / Docker Engine AuthZ bypass** — [GHSA-x744-4wpc-v9h2 / CVE-2026-34040](https://github.com/advisories/GHSA-x744-4wpc-v9h2): an incomplete fix for CVE-2024-41110. Specially crafted oversized Docker API requests can be forwarded to authorization plugins without the request body. AuthZ plugins that inspect bodies to deny dangerous actions may allow requests they would otherwise reject. Fixed in `github.com/moby/moby` / `github.com/docker/docker` `29.3.1` and `github.com/moby/moby/v2` `2.0.0-beta.8`.
- **electerm local service command execution** — [GHSA-x73w-g8hx-v7rp / CVE-2020-23256](https://github.com/advisories/GHSA-x73w-g8hx-v7rp): `electerm <=1.3.22` accepted unverified requests to its service that could execute arbitrary commands. Treat this as part of the existing electerm terminal-client execution boundary, alongside later renderer, link-click, sync, widget, and filename-to-command advisories.

The same scan also saw updated Fabric SDK Java deserialization, HJSON, Scrapy, and Werkzeug resource advisories. Fabric SDK Java is already tracked separately, and the parser/resource-only items did not add enough offensive operator value for a new page.

## Operator triage

1. Identify Docker daemons where AuthZ plugins enforce policy from request bodies, especially around `POST /containers/create`, build, exec, archive, volume, network, and plugin-management endpoints.
2. Confirm whether any Docker API access is exposed to CI runners, tenant jobs, developer workstations, container escape labs, remote TCP sockets, or socket-proxy services. Body-sensitive AuthZ is not a safe primary boundary until patched.
3. Inventory `electerm` on developer laptops, jump boxes, shared admin desktops, and automation hosts. Prioritize old packaged builds and systems that leave a local app/service endpoint reachable beyond the current desktop session.
4. Fold `GHSA-x73w-g8hx-v7rp` into the existing electerm review set; do not clear a workstation just because it is unaffected by only one electerm advisory.

## Replayable validation boundaries

- **Docker AuthZ body boundary:** in a lab daemon with a body-inspecting AuthZ plugin, replay allowed and denied API calls with normal, oversized, chunked, and intentionally body-heavy payloads. The plugin must receive the same canonical body for the authorization decision, and denied actions must stay denied when the body is large.
- **Docker socket-proxy boundary:** test every proxy or broker in front of the Docker API with oversized bodies and streaming uploads. Proxies must not strip, truncate, or reclassify request bodies before policy enforcement.
- **Terminal-client service boundary:** from an unprivileged local user and from any network namespace that can reach the electerm service, attempt unauthenticated service requests with benign commands in an isolated VM. The service must require authenticated, user-scoped intent before any command runner or shell helper is reachable.
- **Terminal config-to-command boundary:** import malicious bookmarks, sync data, filenames, widget paths, and terminal-output links into a disposable electerm profile. No field should become shell syntax, protocol launch, editor execution, or renderer environment exposure.

## Reporting heuristic

For Docker findings, report the exact authorization predicate that failed: the API endpoint, body fields the policy expected to see, body size/transfer mode that changed plugin visibility, and the dangerous action that became allowed. For electerm findings, report the local trust edge: who can reach the service, which request primitive reaches command execution, and what user context the command inherits.

## Durable controls

- Treat Docker API body inspection as a fragile security boundary; authorization should fail closed if the body is missing, truncated, too large, streamed unexpectedly, or cannot be canonicalized.
- Keep Docker sockets away from tenants and untrusted CI even when AuthZ plugins are present. AuthZ is a mediation layer, not a substitute for socket isolation.
- Terminal clients are command brokers. Local services, renderer bridges, imported profiles, filenames, widgets, and clicked links must all authenticate intent and pass literal argv rather than shell text.
- For jump boxes, prefer minimal terminal tooling, no shared privileged desktop sessions, and rapid teardown of profiles/sync state after assessments.
