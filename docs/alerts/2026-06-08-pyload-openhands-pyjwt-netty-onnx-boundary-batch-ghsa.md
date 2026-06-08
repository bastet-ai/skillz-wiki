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
