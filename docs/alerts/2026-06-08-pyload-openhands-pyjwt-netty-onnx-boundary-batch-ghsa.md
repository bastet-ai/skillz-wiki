# pyLoad, OpenHands, PyJWT, Netty, and ONNX boundary batch

Source: hourly offensive-security scan, 2026-06-08. Primary entries: GitHub advisories [GHSA-q485-cg9q-xq2r](https://github.com/advisories/GHSA-q485-cg9q-xq2r), [GHSA-w7hq-f2pj-c53g](https://github.com/advisories/GHSA-w7hq-f2pj-c53g), [GHSA-6px9-j4qr-xfjw](https://github.com/advisories/GHSA-6px9-j4qr-xfjw), [GHSA-ppvx-rwh9-7rj7](https://github.com/advisories/GHSA-ppvx-rwh9-7rj7), [GHSA-7h8w-hj9j-8rjw](https://github.com/advisories/GHSA-7h8w-hj9j-8rjw), [GHSA-752w-5fwx-jx9f](https://github.com/advisories/GHSA-752w-5fwx-jx9f), [GHSA-3qp7-7mw8-wx86](https://github.com/advisories/GHSA-3qp7-7mw8-wx86), [GHSA-p433-9wv8-28xj](https://github.com/advisories/GHSA-p433-9wv8-28xj), [GHSA-hqmj-h5c6-369m](https://github.com/advisories/GHSA-hqmj-h5c6-369m), [GHSA-q56x-g2fj-4rj6](https://github.com/advisories/GHSA-q56x-g2fj-4rj6), [GHSA-838g-gr43-qqg9](https://github.com/advisories/GHSA-838g-gr43-qqg9), [GHSA-97r3-5w84-r4q8](https://github.com/advisories/GHSA-97r3-5w84-r4q8), [GHSA-pg67-9wjv-mr85](https://github.com/advisories/GHSA-pg67-9wjv-mr85), [GHSA-ccxc-x975-4hh9](https://github.com/advisories/GHSA-ccxc-x975-4hh9), [GHSA-mp82-fmj6-f22v](https://github.com/advisories/GHSA-mp82-fmj6-f22v), and [GHSA-mvwx-582f-56r7](https://github.com/advisories/GHSA-mvwx-582f-56r7).

This batch is durable because the items share reusable operator patterns: localhost-only API bypass through `Host` trust, download-manager file-write-to-script execution, agent runtime command injection, JWT critical-header validation gaps, IPv6 subnet-filter bypasses, and ML model repository/file-boundary checks.

## What changed

- **pyLoad local-check bypass** — pyLoad's Click'N'Load routes are intended for localhost clients, but the advisory describes a `@local_check` implementation that trusts user-controlled host/origin data. External attackers can reach local-only download APIs and queue arbitrary URLs, creating SSRF and denial-of-service primitives.
- **pyLoad download-to-script RCE chain** — the `/flashgot` API can be combined with script-folder download destinations and executable download permissions so a completed download lands under `~/.pyload/scripts` and is run by pyLoad's event hooks.
- **pyLoad package-folder traversal, archive extraction, and outbound proxy/TLS setting gaps** — authenticated users with lower permissions can abuse insufficient `pack_folder` normalization, incomplete tar extraction prefix checks, unrestricted `proxy.*` / `ssl_verify` settings, admin-only option-name mismatches, or `X-Forwarded-Proto` global-state races to write outside intended directories or redirect/degrade outbound traffic.
- **OpenHands git diff command injection** — an authenticated `path` parameter flowing into `get_git_diff()` reaches a shell command in the agent sandbox, bypassing the normal agent-command channel.
- **PyJWT unknown `crit` acceptance** — PyJWT accepts JWS tokens that list unsupported critical header extensions instead of rejecting them. This is a validation-boundary finding: impact depends on an application or identity gateway relying on PyJWT where critical header processing semantics matter.
- **Netty IPv6 subnet-filter bypass** — Netty's `IpSubnetFilterRule` comparator can mask against the configured network address instead of the subnet mask, allowing valid public IPv6 addresses to bypass IPv6 allow/deny subnet rules.
- **ONNX model file boundaries** — ONNX external data loading can follow symlinks outside the model directory, `save_external_data` has time-of-check/time-of-use arbitrary file read/write risk around external data files, and `onnx.hub.load(..., silent=True)` can suppress untrusted repository prompts while relying on a hash manifest controlled by the same repository.

## Operator triage

1. **Find exposed pyLoad panels and CNL routes:** fingerprint pyLoad WebUI hosts, `/flashgot`, and Click'N'Load/CNL paths. Prioritize instances reachable beyond localhost, shared VPNs, home-lab targets, seedboxes, NAS deployments, and bug-bounty assets that expose pyLoad behind a reverse proxy.
2. **Check pyLoad role boundaries before impact testing:** distinguish unauthenticated CNL access, authenticated low-privilege settings access, and users with package-modify rights. The strongest reports show a privilege boundary crossed before any file write or script execution.
3. **Map agent control planes:** for OpenHands, find exposed conversation/file APIs, `/api/conversations/{id}/git/diff`, workspace preview environments, and deployments that let untrusted users create or join conversations.
4. **Inventory JWT libraries at auth boundaries:** identify Python services using PyJWT for JWS validation, especially gateways that accept third-party tokens, BYOIDC connectors, custom claims-processing extensions, or policy engines where `crit` should be enforced.
5. **Hunt IPv6 access-control assumptions:** look for Netty-based edge services, Java gateways, or custom servers using `IpSubnetFilterRule` for IPv6 allowlists/denylists. Prioritize assets where IPv4 filtering is tested but IPv6 behavior is not.
6. **Treat ML models as active input:** for ONNX, focus on services that load user-supplied models, pull models from user-controlled GitHub repos, or process model archives during CI, notebooks, evaluation sandboxes, or agent toolchains.

## Replayable validation boundaries

### pyLoad local API, SSRF, and script execution

- Start with non-invasive fingerprinting: title strings, static assets, login redirects, route existence, and HTTP status differences for `/flashgot` or CNL endpoints.
- For local-check bypass validation, use a tester-controlled URL such as an HTTPS canary endpoint. Capture only the inbound callback, requested path, and source IP class. Do not target cloud metadata, internal admin panels, or third-party hosts.
- For download-to-script RCE validation, use a lab clone or explicit written authorization. Use a harmless shell script that writes a marker to a disposable temp directory; do not persist, beacon, or modify real pyLoad hooks on production systems.
- For traversal and extraction checks, write only canary content into target-provided scratch paths. Report the normalized path escape, archive member form, and required permission (`MODIFY`, `SETTINGS`, or unauthenticated CNL) separately from impact.
- For outbound proxy/TLS settings checks, use tester-controlled HTTP/DNS canaries and a disposable destination. Do not proxy production victim traffic or weaken TLS verification outside an approved lab.

### OpenHands git diff command injection

- Verify the API route and authentication requirements first. A version string is weaker than a reachable conversation API with a controlled workspace.
- Use a benign command marker inside the sandbox, such as writing `openhands-diff-canary` to `/tmp` or resolving a DNS canary. Avoid reading workspace secrets, tokens, `.env` files, SSH keys, or cloud metadata.
- Capture the exact `path` parameter shape, response status, sandbox identity, and whether the command bypassed normal tool policy/audit channels.
- If the target intentionally lets users run arbitrary agent commands, frame the report around policy bypass, audit bypass, tenant boundary impact, or unexpected sandbox reach rather than generic command execution.

### PyJWT `crit` header validation

- Build a synthetic signed token in a lab with a `crit` array naming an unsupported header extension and a normal baseline token using the same signing key.
- A vulnerable validation path accepts both tokens. A robust path rejects the unsupported-critical-header token before application claims handling.
- Impact evidence should connect acceptance to a real trust decision: authorization bypass preconditions, policy downgrade, token translation, or interoperability with an upstream issuer that relies on critical headers.
- Do not include production signing keys, real bearer tokens, or customer claims in the report. Use toy keys and sanitized request transcripts.

### Netty IPv6 subnet filter

- Confirm the target uses Netty's `IpSubnetFilterRule` or a dependent framework that delegates IPv6 access control to it.
- Validate with paired source addresses in an authorized lab or target-provided test harness: one address expected to be blocked and one crafted public IPv6 address that bypasses because of incorrect mask handling.
- Avoid disruptive scanning. A single accepted request to a protected test route plus control evidence is enough.
- Report the rule configuration shape, client IP evidence, and whether IPv4 rules behave differently.

### ONNX symlink and hub-loading checks

- Use a local harness or sandboxed service account when testing model loading. Model files are untrusted active content for this workflow.
- For external data symlink traversal and `save_external_data` TOCTOU checks, create a model directory containing synthetic canary files and symlinks in a local sandbox. Prove the loader or writer crosses the intended model directory boundary without touching sensitive files.
- For `onnx.hub.load(..., silent=True)`, demonstrate that an untrusted repository reference loads without prompt and that the hash manifest is repository-controlled. Do not fetch or execute attacker code from public repos during validation; use a private test repo or local mirror.
- Capture call sites, repository strings, loader flags, and file paths. The finding is strongest when user-controlled model references reach automated evaluation, CI, notebook, or agent pipelines.

## Reporting heuristics

- Lead with **boundary evidence**: intended trust boundary, required role, exact endpoint or call site, and how the advisory pattern crosses it.
- Keep impact proofs canary-only. Do not dump files, secrets, model weights, OAuth/JWT material, or internal URLs.
- Chain only when the chain is explicitly in scope: pyLoad local-check bypass to SSRF, pyLoad file write to script execution, ONNX model load to out-of-directory read, or OpenHands API parameter to sandbox command marker.
- Include negative controls: normal versus spoofed `Host`, safe versus traversal package folders, supported versus unsupported JWT `crit`, IPv4 versus IPv6 filter behavior, and trusted versus untrusted ONNX repository loading.

## Notes on skipped items from this scan

- Duplicate/withdrawn advisories, historical low-context entries, and availability-only DoS items were marked processed without standalone publication.
- Sentry client-secret error leakage, Pretalx/Pretix data or email issues, and Plone open redirects may be useful in narrow programs but did not add a reusable workflow beyond existing identity, data-exposure, and open-redirect testing patterns in this wiki.
- Trail of Bits' working RSS endpoint is `https://blog.trailofbits.com/feed/`; the older `feed.xml` path returned 404 during this scan.

## June 28 pyLoad session, CSRF, and localhost-bypass update

GitHub Advisory Database updates added three adjacent pyLoad control-plane items that extend the existing pyLoad validation workflow: [GHSA-fj52-5g4h-gmq8](https://github.com/advisories/GHSA-fj52-5g4h-gmq8), [GHSA-pgpj-v85q-h5fm](https://github.com/advisories/GHSA-pgpj-v85q-h5fm) / CVE-2024-22416, and [GHSA-x698-5hjm-w2m5](https://github.com/advisories/GHSA-x698-5hjm-w2m5) / CVE-2025-7346.

These are worth folding into the pyLoad page because they are not isolated bugs; they expose the same durable operator boundary from different angles: browser sessions, GET-based API calls, and caller-controlled localhost indicators all reaching a download-manager control plane that can create users, retain revoked privileges, or add arbitrary packages.

### Added operator checks

| Advisory | Boundary | Operator value |
| --- | --- | --- |
| [GHSA-fj52-5g4h-gmq8](https://github.com/advisories/GHSA-fj52-5g4h-gmq8) | permission changes did not invalidate or re-scope an already-authenticated pyLoad browser session | When pyLoad permissions are lowered or removed, test whether the existing session can still perform formerly allowed package, settings, or admin actions. |
| [GHSA-pgpj-v85q-h5fm](https://github.com/advisories/GHSA-pgpj-v85q-h5fm) / CVE-2024-22416 | pyLoad API actions accepted GET requests with ambient browser cookies and insufficient CSRF protection | Validate whether admin-only API calls can be triggered cross-site from a victim browser; use inert state changes such as creating a disposable lab user or toggling a reversible setting only. |
| [GHSA-x698-5hjm-w2m5](https://github.com/advisories/GHSA-x698-5hjm-w2m5) / CVE-2025-7346 | localhost-only Click'N'Load/CNL routes trusted spoofable `Host` material such as `127.0.0.1:9666` | Re-test CNL and local-only routes with paired external requests: normal external `Host` should fail, spoofed localhost `Host` should not grant package creation. |

### Safe replay boundaries

1. **Session re-scope:** log in as a disposable high-permission pyLoad user, keep the browser session alive, remove that user's permissions from an admin session, then call harmless endpoints that should now be denied. Evidence is route/status/action parity before and after revocation; do not download third-party content or alter production queues.
2. **CSRF API:** host a minimal same-origin-lab HTML form or image/request harness that targets a reversible pyLoad API action. Prefer a disposable lab instance and actions that create only canary users/packages. Do not publish working admin-takeover payloads for production targets.
3. **Host-based localhost bypass:** send paired requests to CNL/local-only routes from outside localhost, varying only the `Host` header. Use a canary package URL you control and capture whether pyLoad queues or fetches it. Do not target cloud metadata, internal panels, or unrelated hosts.
4. **Negative controls:** sessions are invalidated or permissions are re-checked on every privileged action; unsafe methods and CSRF tokens are enforced for API state changes; local-only checks trust the socket peer address or authenticated reverse-proxy metadata, not raw `Host`/origin headers.

Adjacent [GHSA-8fm5-gg2f-f66q](https://github.com/advisories/GHSA-8fm5-gg2f-f66q) was processed without promotion because the Publify redirect-link XSS requires a publisher-controlled admin click and does not add a stronger workflow beyond existing trusted-admin-render checks.

## July 9 pyLoad IPv6 transition-address SSRF update

GitHub Advisory Database added [GHSA-m5x5-28jr-gpjj](https://github.com/advisories/GHSA-m5x5-28jr-gpjj), which extends the same pyLoad outbound-fetch boundary: an SSRF guard can classify direct private IPs correctly while missing IPv6 transition wrappers such as 6to4 or NAT64 forms that route to the same internal destination.

### Added operator checks

1. **Find every pyLoad feature that fetches caller-supplied URLs.** Include CNL/package URLs, plugin downloaders, link collectors, archive importers, and URL-check helpers.
2. **Build a canonicalization decision table.** For each candidate URL, record parser output, DNS result if applicable, normalized address family, and final socket destination. Include direct private IPv4, IPv4-mapped IPv6, 6to4, NAT64, bracketed IPv6, decimal/octal IPv4, and redirect-to-transition-address controls.
3. **Use only owned canaries.** In an approved lab, route transition-address tests to synthetic services you control. If the customer wants an internal-destination proof, use a purpose-built canary service, not metadata endpoints, admin panels, NAS devices, or other production internals.
4. **Pair with patched negative controls.** A robust guard resolves and normalizes every hop to a concrete address, rejects private/link-local/loopback targets after transition decoding, and repeats the check after redirects.

Evidence should be the parser-vs-socket mismatch and a harmless callback or canary response. Do not turn this into broad internal port scanning or credential collection.
