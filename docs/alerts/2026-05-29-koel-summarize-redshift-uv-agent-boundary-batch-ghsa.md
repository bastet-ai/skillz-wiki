# Koel podcast SSRF, Summarize daemon/file boundaries, Redshift rogue-server RCE, uv entry-point write, MLflow artifact tamper, russh auth state, and AgenticMail boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-7j2f-6h2r-6cqc](https://github.com/advisories/GHSA-7j2f-6h2r-6cqc) / CVE-2026-47260, [GHSA-2r69-qgv3-hr65](https://github.com/advisories/GHSA-2r69-qgv3-hr65) / CVE-2026-45245, [GHSA-8jr4-6r33-phwm](https://github.com/advisories/GHSA-8jr4-6r33-phwm) / CVE-2026-45242, [GHSA-29h4-r29x-hchv](https://github.com/advisories/GHSA-29h4-r29x-hchv) / CVE-2026-8838, [GHSA-4gg8-gxpx-9rph](https://github.com/advisories/GHSA-4gg8-gxpx-9rph), [GHSA-f2m9-wcf4-cwwx](https://github.com/advisories/GHSA-f2m9-wcf4-cwwx) / CVE-2026-4137, [GHSA-hpv4-5h6f-wqr3](https://github.com/advisories/GHSA-hpv4-5h6f-wqr3) / CVE-2026-46705, and [GHSA-wjjv-3mj2-39hf](https://github.com/advisories/GHSA-wjjv-3mj2-39hf) / CVE-2026-47255.

This batch is durable because it captures reusable offensive validation patterns: feed-level URL validation that misses nested media URLs, browser-extension trusted-event and local-daemon request boundaries, authenticated arbitrary file writes from helper endpoints, rogue database server response parsing into client-side code execution, package-installer entry-point path traversal, shared-model-artifact tampering, SSH authentication state confusion across principals, and agent mail/storage SQL plus outbound SMTP/TLS boundaries.

## What changed

- **Koel podcast enclosure SSRF** — Koel validates the podcast feed URL with `SafeUrl`, but stores episode `<enclosure url="...">` values without equivalent checks. When a user plays an episode, server-side playback can `Http::sink()->get()` the enclosure URL and stream the full internal response back to the user.
- **Summarize hover-summary daemon request boundary** — `@steipete/summarize <0.15.0` allowed malicious web pages to dispatch synthetic `mouseover` events over attacker-controlled links. The extension could then make authenticated daemon requests with stored tokens and route local or private-network URLs through the daemon.
- **Summarize `slidesDir` path traversal** — `@steipete/summarize <0.15.0` allowed authenticated callers of `/v1/summarize` to supply absolute paths or traversal sequences in `slidesDir`, writing `slide_*.png` and `slides.json` outside the intended directory and deleting matching files during repeat extraction.
- **Redshift Python connector rogue-server RCE** — `redshift-connector <=2.1.13` insufficiently validates query-result data received over the PostgreSQL wire protocol. A rogue server or MITM can craft responses that reach an `eval()` injection path in the client process.
- **uv entry-point arbitrary file write** — `uv <0.11.15` honored malicious wheel `console_scripts` or `gui_scripts` entry-point names that escaped the environment scripts directory, potentially placing executables in PATH-visible locations even when the install environment was not intentionally activated.
- **MLflow shared temporary artifact tamper** — `mlflow <3.11.0` created model-download temporary directories with world-writable or group-writable permissions, enabling local attackers on shared NFS-style environments to replace model artifacts such as cloudpickle payloads before deserialization.
- **russh userauth principal state drift** — `russh` kept library-owned auth state across `SSH_MSG_USERAUTH_REQUEST` messages even when the username or service changed, creating a state-confusion boundary around remaining methods, partial success, and in-progress auth method state.
- **AgenticMail API/storage and outbound relay boundaries** — `@agenticmail/api` and `@agenticmail/core` fixes cover bounded inactive-agent filtering, SQL identifier validation, metadata-backed ownership checks for raw storage SQL, raw metadata access blocking, fail-closed outbound worker secrets, SMTP envelope/header control-character validation, and TLS certificate verification defaults.

## Operator triage

1. **Find feed ingestion that performs deferred media fetches:** Koel is the concrete target, but the pattern generalizes to podcast, RSS, playlist, and import features that validate only the outer feed URL.
2. **Prioritize full-read SSRF impact:** Koel's playback path can download and stream response bodies, so internal HTTP services, cloud metadata routes, and unauthenticated admin panels are higher-value than blind callback-only SSRF.
3. **Map extension-to-daemon trust:** for Summarize, identify browser-extension installs, local daemon endpoints, stored daemon tokens, and web-page interactions that can trigger privileged local requests.
4. **Look for authenticated helper endpoints with filesystem parameters:** `slidesDir` is interesting when a web page, local user, or lower-privileged workflow can call the daemon with an existing token.
5. **Review data clients that connect to user-supplied hosts:** Redshift connector impact requires a client that can be pointed at an attacker-controlled PostgreSQL/Redshift-compatible endpoint or intercepted in transit.
6. **Trace Python package installation in agents and CI:** uv entry-point traversal matters when untrusted wheels, private indexes, generated lockfiles, or project-controlled dependencies are installed on hosts with PATH-sensitive automation.
7. **Separate MLflow local/NFS escalation from remote model loading:** this item is strongest in shared notebook, Databricks, NFS, or multi-user ML workers where one local actor can race/tamper with another user's model download cache.
8. **Check SSH servers built on russh:** focus on services that expose public-key plus keyboard-interactive or multi-step auth, especially where application handlers assume russh resets state per `(user, service)`.
9. **Treat AgenticMail as an agent-control-plane review target:** raw storage SQL, metadata ownership, SMTP command construction, and TLS verification defaults are all boundaries worth regression-testing in mail-agent products.

## Replayable validation boundaries

### Koel podcast enclosure SSRF check

- **Host a benign public podcast feed:** keep the feed URL itself on a public tester-controlled host so the outer `SafeUrl` check passes.
- **Point only the enclosure at a canary target:** use a tester-owned callback endpoint first, then an explicitly authorized lab-only internal URL if body-read proof is required.
- **Trigger normal playback:** subscribe to the feed and play the episode; capture the server-side request to the enclosure URL and, if authorized, the streamed response body.
- **Avoid production internal probing:** do not enumerate internal ports or read sensitive metadata on production systems. A single controlled callback plus version/path evidence is enough for most reports.

### Summarize trusted-event daemon request check

- **Confirm local extension/daemon architecture:** record extension version, daemon endpoint, token storage, and the hover-summary feature path.
- **Use a synthetic page:** create an attacker-controlled page that dispatches synthetic hover events over a URL pointing to a tester-owned callback.
- **Prove daemon mediation:** show that the daemon, not the browser page directly, issued the authenticated request. Use callback headers, source IP, or request timing as evidence.
- **Escalate internal reach only in lab:** if demonstrating local/private URL access, use a disposable service under tester control on loopback or a lab private network.

### Summarize `slidesDir` file-write check

- **Require an authorized daemon token:** this is an authenticated local/API boundary; do not brute-force tokens.
- **Use disposable temp paths:** submit `slidesDir` pointing to a lab temp directory outside the intended output root and verify creation of `slide_*.png` / `slides.json` canaries.
- **Test cleanup impact safely:** repeat extraction only against synthetic files matching the expected generated names.
- **Report path normalization:** include absolute-path and `../` behavior, daemon version, endpoint, and caller privilege assumptions.

### Redshift connector rogue-server RCE check

- **Keep the server under tester control:** run a minimal PostgreSQL-wire-compatible lab endpoint or use the published PoC only in an isolated environment.
- **Use a harmless marker payload:** demonstrate code execution with a canary file in a temp directory or a tester-owned callback, not credential or filesystem harvesting.
- **Prove client-side execution:** capture the connector version, connection string source, query path, and evidence that the payload executed in the client process.
- **Tie to attacker influence:** reports are strongest when a tenant, config file, environment variable, CI secret, or user input can influence the database host or trust path.

### uv entry-point arbitrary file-write check

- **Build a controlled wheel:** create a lab wheel with a `console_scripts` or `gui_scripts` entry-point name that attempts to escape the scripts directory to a temp canary path.
- **Install with vulnerable uv:** use `uv <0.11.15` in a disposable virtualenv or container; record the generated file path relative to the intended scripts directory.
- **Avoid overwriting real executables:** never target system PATH or developer tools on a live host. Use an isolated PATH directory mounted for the test.
- **Report installation context:** identify whether the target workflow installs untrusted wheels, consumes private indexes, or runs package installs in agents/CI with persistent PATH entries.

### MLflow shared temporary artifact tamper check

- **Use a shared lab directory:** reproduce with two low-privileged lab users or containers sharing an NFS-like model cache.
- **Race/tamper only synthetic artifacts:** replace a test cloudpickle artifact with a payload that writes a harmless marker.
- **Demonstrate deserialization trigger:** show the victim MLflow process loading the tampered artifact and executing only the benign marker.
- **Scope impact carefully:** frame this as local/shared-environment escalation unless paired with a separate primitive that lets a remote actor write to the temp directory.

### russh auth-state drift check

- **Instrument a test russh server:** use a lab service that logs username, service, auth method state, partial-success flags, and remaining-method lists.
- **Switch principals mid-auth:** send a valid sequence of `SSH_MSG_USERAUTH_REQUEST` messages where username or service changes between method attempts.
- **Look for state carryover:** verify whether remaining methods, partial success, keyboard-interactive state, or public-key offer state influence the second principal.
- **Do not attack production SSH:** this is protocol-state testing; run it against a lab instance or a program-explicit test endpoint.

### AgenticMail storage and relay boundary check

- **Use synthetic tenants and messages:** create two test users/agents with non-sensitive metadata and mail content.
- **Exercise raw storage SQL controls:** attempt identifier injection, cross-owner raw queries, and metadata-table access with benign canary rows.
- **Validate SMTP command construction:** send envelope/header fields containing CRLF/control-character canaries to confirm rejection before SMTP command assembly.
- **Check TLS defaults:** ensure outbound MailSender verifies certificates by default and that opt-out paths are explicit, logged, and local-development scoped.

## Reporting heuristics

- For Koel, emphasize that the validated URL and the fetched URL are different trust boundaries. Include the safe feed URL, enclosure URL, playback trigger, callback/body proof, and affected version.
- For Summarize, separate browser-origin abuse from daemon filesystem abuse. Include event-trust assumptions, token/daemon requirement, request source evidence, and file-write path proof.
- For Redshift connector, show a realistic path for attacker-controlled server selection or MITM; a vulnerable library version alone is not enough.
- For uv, include the malicious entry-point metadata, intended scripts directory, actual written path, and whether the path is executable or PATH-visible in the target workflow.
- For MLflow, document local/shared prerequisites and avoid overstating it as unauthenticated remote RCE unless another remote-write primitive exists.
- For russh, report precise protocol sequence and state carryover, not only that usernames changed between attempts.
- For AgenticMail, group findings by boundary: storage SQL, ownership metadata, outbound secret handling, SMTP injection, and TLS verification.

## Notes on skipped items from this scan

- zeroconf exception-retention and compression-pointer recursion advisories were reviewed as LAN-local memory/DoS issues without a durable Skillz operator workflow.
- Nerdbank.MessagePack CPU and memory amplification advisories were reviewed as resource-exhaustion hardening items.
- Sparkle XPC spoofed appcast item injection and binary-delta intermediate-symlink traversal were tracked as macOS update-chain hardening signals, but not promoted into validation guidance here because one path is a tight local race/UI-spoofing issue and the stronger file-write path requires malicious delta signing-key control.
- go-git malformed-object panics/resource exhaustion and russh oversized compressed-packet DoS were reviewed as availability-focused and not standalone for this taxonomy.
- Summarize missing-authorization companion advisories were covered only as context for the stronger trusted-event and file-write paths above.
- CISA KEV stayed catalog `2026.05.29` with CVE-2026-0257 already reflected in the previous Skillz update. PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits `/feed.xml`, and Disclosed had no separate promotable deltas in this pass.
