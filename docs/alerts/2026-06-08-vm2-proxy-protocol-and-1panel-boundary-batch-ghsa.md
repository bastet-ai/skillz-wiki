# vm2 WASM, SMTP PROXY, and 1Panel file-write boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-06-08: [GHSA-ffh4-j6h5-pg66](https://github.com/advisories/GHSA-ffh4-j6h5-pg66) / CVE-2026-26956, [GHSA-c2c3-pqw5-5p7c](https://github.com/advisories/GHSA-c2c3-pqw5-5p7c) / CVE-2025-31135, and [GHSA-f8ch-w75v-c847](https://github.com/advisories/GHSA-f8ch-w75v-c847) / CVE-2024-34352.

This batch is durable because it captures three reusable operator patterns: JavaScript sandbox escapes gated by modern runtime features, SMTP PROXY-protocol trust-boundary spoofing, and admin/image workflow file-write primitives that can become RCE when user-controlled configuration is passed to shell-like helpers.

## What changed

- **vm2 WASM sandbox escape** — `vm2 3.10.4` on Node.js versions with WebAssembly exception handling and `JSTag` support was reported to allow attacker-controlled code passed to `VM.run()` to reach the host `process` object and execute host commands. Treat this as a runtime-feature-gated sandbox escape, not a generic version-only finding.
- **Go-Guerrilla SMTP PROXY command override** — when `ProxyOn` is enabled, Go-Guerrilla accepted multiple `PROXY` commands. Later commands could override the client IP address originally supplied by the trusted edge proxy, turning allowlists, rate limits, abuse attribution, and policy checks that trust the proxy-derived source IP into validation targets.
- **1Panel image/mirror configuration file write** — 1Panel exposed command-injection/arbitrary-file-write behavior through image/mirror configuration handling, including shell redirection-style payloads. In admin or delegated-control contexts, file writes may become RCE if they land in startup scripts, cron-like paths, web roots, or application configuration consumed by privileged processes.

## Operator triage

1. **Find sandbox-as-security-boundary surfaces:** workflow builders, plugin systems, agent tools, template/code runners, notebook products, and SaaS scripting features that advertise `vm2`, `VM`, or `NodeVM` isolation.
2. **Capture runtime gates:** record the `vm2` version, Node.js version, whether WebAssembly is enabled, and whether the runtime exposes WebAssembly exception-handling / `JSTag` features. Avoid reporting a WASM-specific escape from version evidence alone.
3. **Map SMTP proxy trust:** identify Go-Guerrilla deployments behind HAProxy, nginx stream, Envoy, or other relays that use PROXY protocol. Confirm whether downstream policy decisions consume the rewritten source IP.
4. **Look for double-PROXY parsing:** compare behavior when the connection begins with one valid `PROXY` line versus one valid line followed by a second attacker-chosen `PROXY` line before normal SMTP commands.
5. **Inventory 1Panel delegated admin paths:** focus on image, registry, mirror, and container configuration inputs that are accepted from tenants, help-desk admins, or CI automation rather than only from trusted root operators.
6. **Trace file-write impact:** determine the destination path, file owner, overwrite/append mode, restart requirement, and whether the written content is later interpreted by a shell, web server, scheduler, container runtime, or application loader.

## Replayable validation boundaries

### vm2 WASM sandbox checks

- Start with dependency and runtime evidence from lockfiles, diagnostics, container images, or package metadata.
- In a dedicated lab tenant, use a harmless host-execution marker such as `id`, `whoami`, or writing a canary file under a disposable temp directory.
- Include a negative control on a runtime without the relevant WebAssembly features, or with WebAssembly disabled, when possible. The report is stronger if it proves the feature gate.
- Do not read environment secrets, SSH keys, cloud metadata, or production files. A synthetic marker is enough to prove the boundary break.

### SMTP PROXY-protocol spoofing checks

- Only test systems where PROXY protocol is expected; sending raw PROXY lines to ordinary SMTP services can disrupt normal handling.
- Use tester-owned source IP markers and a mail transaction that never leaves the authorized test environment.
- Validate whether the second `PROXY` line changes logs, rate-limit buckets, allow/deny decisions, authentication throttles, or downstream policy headers.
- Preserve packet captures or transcript snippets that show command ordering without including real customer addresses or message content.

### 1Panel file-write checks

- Prefer a lab clone or explicit tenant-scoped test instance. File-write validation can be destructive if paths are guessed.
- Use a canary destination under a disposable directory first; escalate to startup/config paths only when scope explicitly permits RCE validation.
- Record whether payloads are appended or overwritten and whether shell metacharacters are interpreted before the write.
- If RCE validation is approved, use a single benign marker command and immediately remove test artifacts.

## Reporting heuristics

- For vm2 findings, include the product feature accepting code, sandbox library/version, Node.js version, WebAssembly feature state, exact benign proof, and why the sandbox is a trust boundary for the application.
- For SMTP PROXY findings, include network topology, `ProxyOn` evidence, first and second PROXY lines used, observed source-IP change, and the policy decision affected by spoofing.
- For 1Panel findings, include the role required, vulnerable configuration field, sanitized canary payload, write target, file permissions, interpreter/restart path, and proof that the write crosses the intended admin or tenant boundary.
- Separate capability proof from impact proof: source-IP spoofing is strongest when tied to a bypassed control, and arbitrary write is strongest when tied to controlled execution or sensitive configuration overwrite.

## Notes on skipped items from this scan

- fscrypt PAM metadata validation (GHSA-p93v-m2r2-4387), CometBFT invalid pre-commit panic (GHSA-p7mv-53f2-4cwj), and Axios recursive `toFormData` crash (GHSA-62hf-57xw-28j9) were marked processed without publication because they are local or availability-first and do not add a distinct offensive operator workflow for this wiki.
- `cryptiles` insufficient entropy (GHSA-rq8g-5pc5-wrhr) was marked processed without publication because the public advisory is a deprecated-package crypto hygiene issue without a replayable validation path beyond version identification.
- Other feeds checked in this run had no separate promotable deltas: PortSwigger stayed on the 2025 top techniques post, Trail of Bits stayed on skill-distribution research, ProjectDiscovery stayed on Neo agent architecture, GitHub Security Blog stayed on GHES signing-key rotation, Disclosed stayed lander-only, and CISA KEV stayed on CVE-2026-28318.
