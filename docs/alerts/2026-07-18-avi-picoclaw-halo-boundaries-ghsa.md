# VMware Avi, PicoClaw, and Halo boundary checks

Sources: hourly offensive-security scan, 2026-07-18 GitHub Security Advisory wave. Primary entries: VMware Avi Load Balancer [GHSA-g2gr-xhcw-h7mc](https://github.com/advisories/GHSA-g2gr-xhcw-h7mc) / CVE-2026-47865, [GHSA-7hx5-4268-25qv](https://github.com/advisories/GHSA-7hx5-4268-25qv) / CVE-2026-47866, [GHSA-cf92-7pc6-48mm](https://github.com/advisories/GHSA-cf92-7pc6-48mm) / CVE-2026-47867, [GHSA-h452-q2fr-5rvh](https://github.com/advisories/GHSA-h452-q2fr-5rvh) / CVE-2026-47869, [GHSA-x69w-rh5r-3wgj](https://github.com/advisories/GHSA-x69w-rh5r-3wgj) / CVE-2026-47870, and [GHSA-m658-jv2r-hm53](https://github.com/advisories/GHSA-m658-jv2r-hm53) / CVE-2026-47871; Sipeed PicoClaw [GHSA-mcj8-ff8h-86ph](https://github.com/advisories/GHSA-mcj8-ff8h-86ph) / CVE-2026-16084 and [GHSA-jj5m-mcrf-wh9m](https://github.com/advisories/GHSA-jj5m-mcrf-wh9m) / CVE-2026-16085; Halo [GHSA-mrpc-g9pq-2433](https://github.com/advisories/GHSA-mrpc-g9pq-2433) / CVE-2026-16088.

This batch is durable for operators because the advisories map to repeatable assessment surfaces: load-balancer control planes where route families cross authentication, authorization, directory, and RCE boundaries; AI/agent integrations where a `web_fetch` tool can make server-side requests from the agent host; agent context builders where local workspace state may enter a trusted control sphere; and migration/backup download endpoints where archive names or paths can escape the intended backup root.

!!! warning "Authorized validation only"
    Keep proofs to owned VMware Avi labs, disposable PicoClaw agent instances, throwaway Halo sites, owned callback hosts, synthetic local services, and marker-only backup files. Do not target production control planes, capture real load-balancer configuration, query metadata services, read backups containing user data, invoke destructive agent tools, or publish weaponized RCE payloads.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-g2gr-xhcw-h7mc](https://github.com/advisories/GHSA-g2gr-xhcw-h7mc) / CVE-2026-47865 | VMware Avi Load Balancer control plane | Network actor may bypass authentication to reach the Avi control plane | Add pre-auth route-family and session-bootstrap checks to exposed Avi assessments. |
| [GHSA-7hx5-4268-25qv](https://github.com/advisories/GHSA-7hx5-4268-25qv) / CVE-2026-47866 | VMware Avi Load Balancer control plane | Network actor may access a limited subset of control-plane routes without proper authorization | Build low-privilege/no-session route matrices instead of testing only login reachability. |
| [GHSA-cf92-7pc6-48mm](https://github.com/advisories/GHSA-cf92-7pc6-48mm) and [GHSA-h452-q2fr-5rvh](https://github.com/advisories/GHSA-h452-q2fr-5rvh) / CVE-2026-47867 and CVE-2026-47869 | VMware Avi Load Balancer | Control-plane inputs may cross into remote code execution conditions | Stop at route, role, and inert marker evidence in lab; do not publish exploit chains. |
| [GHSA-x69w-rh5r-3wgj](https://github.com/advisories/GHSA-x69w-rh5r-3wgj) and [GHSA-m658-jv2r-hm53](https://github.com/advisories/GHSA-m658-jv2r-hm53) / CVE-2026-47870 and CVE-2026-47871 | VMware Avi Load Balancer | Authenticated users may cross privilege or filesystem path boundaries | Test role scoping and directory traversal with synthetic objects/files only. |
| [GHSA-mcj8-ff8h-86ph](https://github.com/advisories/GHSA-mcj8-ff8h-86ph) / CVE-2026-16084 | Sipeed PicoClaw `pkg/tools/integration/web.go` `web_fetch` | Agent/web-integration URL input reaches server-side fetch behavior | Treat AI/agent web-fetch tools as SSRF surfaces with final-destination and response-reflection controls. |
| [GHSA-jj5m-mcrf-wh9m](https://github.com/advisories/GHSA-jj5m-mcrf-wh9m) / CVE-2026-16085 | Sipeed PicoClaw `pkg/agent/context.go` `NewContextBuilder` | Local manipulation may include functionality from an untrusted control sphere | Assess repository/workspace-to-agent context trust before invoking tools. |
| [GHSA-mrpc-g9pq-2433](https://github.com/advisories/GHSA-mrpc-g9pq-2433) / CVE-2026-16088 | Halo `MigrationEndpoint.java` backup download | Files-backup download path can traverse outside intended migration artifacts | Add backup/export download path-normalization checks to CMS and migration reviews. |

## Replayable validation boundaries

### VMware Avi control-plane route-family matrix

1. Confirm explicit authorization and test only an owned Avi lab or customer-approved appliance window.
2. Fingerprint the Avi version and control-plane exposure with passive headers, login-page metadata, and vendor-supported version evidence where available.
3. Build a route matrix with the same endpoint families exercised as unauthenticated, low-privileged authenticated, and intended administrator users.
4. Use harmless read-only or synthetic routes first: login/session bootstrap, health/status, object-list endpoints in a lab tenant, file/download handlers with marker files, and any vendor-documented API that should require a role.
5. For RCE-labeled entries, stop at precondition evidence: reachable route, required role, accepted parameters, and a lab-only inert marker such as an echoed nonce or rejected dry-run command. Do not attempt production command execution.
6. For directory traversal, request only disposable marker files created for the test, and include patched-version or denied-route negative controls.

Report this as **network/control-plane route -> missing authz/authn or path validation -> privileged Avi surface reached**. Strong evidence is a table with route, method, actor role, expected decision, observed status/body marker, and fixed or non-vulnerable control.

### PicoClaw `web_fetch` SSRF checks

1. Run PicoClaw in a disposable lab with no cloud credentials and egress limited to owned callback infrastructure plus synthetic local canary services.
2. Invoke the `web_fetch` integration first against an owned public callback URL to prove the agent host performs the request.
3. Repeat with redirect chains, DNS rebinding fixtures, IPv4-mapped IPv6 notation, and a lab-owned private canary only if the engagement authorizes SSRF guard testing.
4. Capture whether the tool follows redirects, classifies the final destination, returns upstream response bodies/errors to the caller, and preserves sensitive request headers across hosts.
5. Add controls for patched builds, denied address classes, blocked schemes, timeouts, and response-size caps.

Report this as **agent tool URL -> server-side fetch from agent host -> callback or response marker observed**. Do not query metadata endpoints, Kubernetes service IPs, internal admin panels, or real third-party services.

### PicoClaw context control-sphere checks

1. Start from a scratch repository/workspace and a disposable PicoClaw profile.
2. Place only inert canary context artifacts in the location consumed by `NewContextBuilder`; the marker should identify source, scope, and expected trust level.
3. Observe whether local workspace-controlled context is loaded into a privileged agent context without an explicit trust decision.
4. Attempt a negative control with an untrusted workspace, a patched build, or a context file outside the expected project boundary.
5. Verify that no dangerous tool invocation occurs during proof; the marker should be log-only or prompt-only.

Report this as **local workspace/control file -> context builder -> trusted agent control sphere**. Pair the finding with tool-invocation impact only when a separate, inert tool-call canary proves the context changes execution decisions.

### Halo migration backup download traversal checks

1. Deploy a throwaway Halo instance with synthetic content and create marker files inside and outside the expected migration/backup artifact root.
2. Authenticate only as the role required by the target backup-download endpoint; if the route is expected to be admin-only, include lower-privileged negative controls.
3. Request a normal backup artifact to record baseline headers, filename handling, and response shape.
4. Attempt traversal or encoded-separator variants that reference only the synthetic outside-root marker file.
5. Capture status code, normalized path decision, returned marker presence/absence, and patched or sanitized-path controls.

Report this as **backup artifact selector -> path normalization failure -> outside-root marker returned**. Never read real backups, configuration files, database exports, user uploads, or environment secrets.

## Operator checklist

- [ ] Did the proof stay within owned/lab Avi, PicoClaw, and Halo assets?
- [ ] Did Avi evidence use route/role/status matrices instead of exploit payloads?
- [ ] Did SSRF testing use owned callbacks and synthetic local services only?
- [ ] Did backup traversal return only marker files created for the test?
- [ ] Did reports redact appliance hostnames, callback tokens, session cookies, route object names, and any non-marker file paths?

## Not promoted from the same wave

Shibby Tomato buffer-overflow advisories, Linux kernel memory-safety updates, barebox parser issues, WordPress CSRF, Windows/Edge exposure notes, and sparse AstrBot/PicoClaw low-detail entries were marked processed without standalone pages because this run did not identify a safer reusable workflow beyond existing appliance route-matrix, parser memory-safety, CSRF, and agent trust-boundary guidance.
