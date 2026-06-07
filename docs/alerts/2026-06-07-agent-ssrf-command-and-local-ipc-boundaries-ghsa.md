# Agent, SSRF, command, and local IPC boundary checks

Source: GitHub Security Advisories REST API, published/updated 2026-06-07.

This batch is durable because it turns sparse but actionable advisories into reusable validation patterns for **agent/tool configuration command injection**, **installation-time SSRF**, **remote log-viewer command injection**, and **local IPC privilege-boundary exposure**. Use these workflows only in authorized labs, staging systems, or explicitly scoped assessments.

## What changed

- **MetaGPT `mermaid.path` command injection** — [GHSA-h4jg-8v58-57wj](https://github.com/advisories/GHSA-h4jg-8v58-57wj) / CVE-2026-11455: advisory text identifies `metagpt/utils/common.py` `check_cmd_exists` handling of the `mermaid.path` argument as a command-injection sink. The useful operator lesson is broader: agent frameworks that accept tool binary paths, renderer paths, or diagram-helper configuration can turn "path validation" into shell execution if the check crosses a command boundary.
- **go-fastdfs-web installation endpoint SSRF** — [GHSA-6g49-gvr8-2cj2](https://github.com/advisories/GHSA-6g49-gvr8-2cj2) / CVE-2026-11437: `/install/checkServer` `checkServer` handling in go-fastdfs-web up to 1.3.7 is described as a remotely reachable SSRF primitive. Treat installer and setup routes as part of the attack surface, especially when internet-exposed panels leave install checks enabled after deployment.
- **vertex-app Vertex log-viewer command injection** — [GHSA-cx7v-5xwm-4mqw](https://github.com/advisories/GHSA-cx7v-5xwm-4mqw) / CVE-2026-11408: the advisory names `app/model/LogMod.js` and `req.query` handling in a Log Viewer endpoint as an OS command-injection path, fixed by commit `805d82e7100d49b79b3beb1b9420e8e458987198`. The reusable pattern is log/UI utilities that shell out using request query parameters.
- **clash-verge-service-ipc world-reachable IPC** — [GHSA-5m7x-g9jc-x5g7](https://github.com/advisories/GHSA-5m7x-g9jc-x5g7) / CVE-2026-26422: versions before 2.3.0 expose an IPC endpoint broadly enough to create a local privilege-escalation boundary. This is useful for workstation/red-team tooling reviews where desktop helper services run with elevated privileges.

## Operator triage

1. Search scoped code and deployment notes for sinks, not just product names:
   - `mermaid.path`, `check_cmd_exists`, `shell=True`, `exec`, `spawn`, `subprocess`, `which`, `where`, and agent/tool configuration that stores renderer or helper-binary paths;
   - `/install/checkServer`, installer routes, setup wizards, "check server" probes, URL/server validation fields, and post-install routes left enabled;
   - log viewer endpoints that accept query parameters for file name, date, tail count, grep/filter pattern, archive path, or service name;
   - local IPC services listening on TCP, Unix sockets, named pipes, or localhost-only HTTP ports from desktop/networking tools.
2. Prioritize systems where low-privileged users can change configuration consumed by a higher-privileged agent, admin UI, installer, or local helper service.
3. For internet-facing recon, treat setup and diagnostic endpoints as first-class SSRF candidates. They are often outside normal application route maps and may be unauthenticated during or after install.
4. Separate primitives clearly: command injection, SSRF, and local IPC privilege crossing require different evidence and impact framing.

## Replayable validation boundaries

### Agent/tool path command-injection canary

Use this for MetaGPT-like `mermaid.path` checks and other agent frameworks that validate helper binaries.

1. In a lab or scoped staging clone, identify the exact configuration path for helper binaries or renderer tools.
2. Replace the helper path with an inert command-separator canary that attempts to create a marker in a disposable directory, such as `/tmp/skillz-agent-path-marker.txt`.
3. Trigger only the validation path or diagram-rendering path needed to reach the helper check.
4. Vulnerable result: the marker is created, or logs show the checker interpreted shell metacharacters rather than treating the value as an executable path.
5. Capture version, config key, user role needed to set it, command/check call site, marker path, and execution identity. Do not run destructive commands or exfiltrate environment variables.

### Installer SSRF canary

Use this for go-fastdfs-web `/install/checkServer` and similar setup probes.

1. Start a lab-owned HTTP/DNS listener reachable by the target, or use an approved collaborator endpoint from the assessment scope.
2. Submit the listener URL or host through the installer/server-check parameter suspected of triggering a backend fetch.
3. Repeat with only safe variations that test parser boundaries: scheme, hostname, port, path, and redirects if allowed by scope.
4. Vulnerable result: the listener receives a request from the application server, or application output proves a backend fetch to the supplied endpoint.
5. Capture request path, parameter name, source IP/user agent, authentication state, and whether the installer route remains reachable after setup. Do not target cloud metadata, internal admin panels, or third-party hosts unless explicitly authorized.

### Log-viewer command-boundary canary

Use this for Vertex-like log utility endpoints and admin diagnostic pages.

1. Identify a query parameter that controls log selection, filtering, service names, or shell-backed tooling.
2. In staging, submit a harmless metacharacter probe that writes a unique marker under a disposable directory or returns a benign timing/log marker.
3. Compare behavior against an expected safe value and against application logs.
4. Vulnerable result: marker creation, command-output reflection, timing consistent with command execution, or logs showing shell interpretation of the query value.
5. Capture the endpoint, method, parameter, authenticated role, execution identity, and fixed version or commit boundary.

### Local IPC exposure boundary

Use this for clash-verge-service-ipc-like helper services on workstations or jump hosts.

1. From the same host, enumerate the helper service binding in a non-invasive way: socket path, TCP address, port, owning user, and process name.
2. From a lower-privileged local account, attempt only documented or benign IPC calls that prove reachability across the intended privilege boundary.
3. If the service should be private to one user, test whether another local user can connect and trigger a harmless status or version call.
4. Vulnerable result: a lower-privileged account can reach an IPC endpoint or method intended for a more privileged user/service context.
5. Capture binding address, filesystem/socket permissions, process identity, caller identity, and benign method invoked. Do not trigger state-changing privileged actions during proof.

## Reporting heuristics

- Frame MetaGPT-style issues as **agent helper-path configuration crossing into command execution**. Strong reports identify who can set the path and which higher-privileged runtime later validates or executes it.
- Frame installer SSRF as **setup/diagnostic routes retained as backend fetch gadgets**. Include whether the route is reachable unauthenticated or after installation.
- Frame log-viewer command injection as **admin/diagnostic UI parameters reaching shell-backed utilities**. Include the minimal parameter and proof that the shell boundary was crossed.
- Frame local IPC exposure as **desktop/helper service privilege-boundary failure**. The impact depends on what methods the lower-privileged caller can reach; do not overclaim beyond the benign method demonstrated.
- The same feed wave included many sparse VulDB-style SQLi/XSS/auth-bypass/router/memory-safety/DoS entries, Chrome memory-safety updates, a rejected CVE, and generic identity/rate-limit items. Those were reviewed but not promoted here because they were too product-specific, local-only without a reusable workflow, memory-safety-only, availability-only, or lacked enough public detail for a durable operator page.

## Sources

- GitHub Advisory Database: [GHSA-h4jg-8v58-57wj / CVE-2026-11455](https://github.com/advisories/GHSA-h4jg-8v58-57wj)
- MetaGPT issue/source: <https://github.com/FoundationAgents/MetaGPT/issues/2037> and <https://github.com/FoundationAgents/MetaGPT>
- GitHub Advisory Database: [GHSA-6g49-gvr8-2cj2 / CVE-2026-11437](https://github.com/advisories/GHSA-6g49-gvr8-2cj2)
- go-fastdfs-web advisory references: <https://vuldb.com/vuln/369017> and <https://www.notion.so/Server-Side-Request-Forgery-SSRF-in-go-fastdfs-web-Installation-Endpoint-35aea92a3c41806485ffeeac7e18126a>
- GitHub Advisory Database: [GHSA-cx7v-5xwm-4mqw / CVE-2026-11408](https://github.com/advisories/GHSA-cx7v-5xwm-4mqw)
- Vertex source/fix references: <https://github.com/vertex-app/vertex> and <https://github.com/vertex-app/vertex/commit/805d82e7100d49b79b3beb1b9420e8e458987198>
- GitHub Advisory Database: [GHSA-5m7x-g9jc-x5g7 / CVE-2026-26422](https://github.com/advisories/GHSA-5m7x-g9jc-x5g7)
- clash-verge-service-ipc release/fix: <https://github.com/clash-verge-rev/clash-verge-service-ipc/releases/tag/v2.3.0> and <https://github.com/clash-verge-rev/clash-verge-rev/commit/3bbcdbe5caacc2ffb713af69f2c93e202573f918>
