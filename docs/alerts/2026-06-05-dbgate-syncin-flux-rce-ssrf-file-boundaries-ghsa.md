# DbGate, Sync-in Server, and Flux source-controller boundary batch

Source: GitHub Security Advisories REST API, published/updated 2026-06-05.

This batch is durable because the advisories map to reusable offensive testing patterns: **database-admin runner input crossing into server-side JavaScript execution**, **archive extraction crossing a filesystem boundary**, **URL download SSRF filters missing IPv4-mapped IPv6 forms**, and **Kubernetes GitOps source ingestion writing or probing outside its reconciliation workspace**. Use these workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **DbGate `load-reader` `functionName` code injection** — [GHSA-wm5r-5qp3-5vxf](https://github.com/advisories/GHSA-wm5r-5qp3-5vxf) / CVE-2026-47670 and [GHSA-hv83-ggc4-v385](https://github.com/advisories/GHSA-hv83-ggc4-v385) / CVE-2026-48017: authenticated callers can submit a `functionName` value to `/runners/load-reader` that is interpolated into a generated JavaScript runner. The `require = null` sandbox hardening can be bypassed with language-level `import()`.
- **DbGate JSON script runner code injection** — [GHSA-8v3q-9vmx-36vc](https://github.com/advisories/GHSA-8v3q-9vmx-36vc) / CVE-2026-47668: `/runners/start` accepts JSON scripts whose `assign` command fields become generated JavaScript. The JSON runner path can skip shell-script permission gates and turn attacker-controlled `functionName`/variable syntax into Node.js execution.
- **DbGate archive Zip Slip to file write/RCE** — [GHSA-h535-j5hr-mv56](https://github.com/advisories/GHSA-h535-j5hr-mv56) / CVE-2026-47669: archive upload/save/unzip paths extract ZIP entries without ensuring the resolved destination remains inside the archive workspace. In default Docker-style deployments, a network-adjacent actor may be able to obtain a token through the `none` auth provider and write files as the DbGate process user.
- **Sync-in Server IPv4-mapped IPv6 SSRF bypass** — [GHSA-q4x5-8cj6-52wg](https://github.com/advisories/GHSA-q4x5-8cj6-52wg) / CVE-2026-47684: the URL download feature checks `request.socket.remoteAddress` against a private-IPv4 regex but misses `::ffff:<ipv4>` forms reported by Node.js on dual-stack systems.
- **Flux source-controller path traversal and sparse-checkout file probe** — [GHSA-jjrm-hr5f-673x](https://github.com/advisories/GHSA-jjrm-hr5f-673x) / CVE-2026-47680: an actor who can influence objects in a referenced bucket can make source-controller write fetched data outside the per-reconciliation working directory. Separately, actors who can create/update `GitRepository` resources on v1.6.0+ can use sparse-checkout status feedback to test for path existence on the controller pod.

## Operator triage

1. Search for exposed DbGate deployments, especially Docker containers with default or bootstrap auth settings, team-shared admin UI access, archive import features, and runner endpoints enabled.
2. Prioritize DbGate where low-privileged users can authenticate but should not run shell scripts, install plugins, write arbitrary files, or affect host/container startup files.
3. Search for Sync-in Server deployments that let users import files by URL. Prioritize dual-stack hosts, Node.js reverse-proxy paths, and environments where the application can reach cloud metadata, loopback services, or RFC1918 admin panels.
4. Search Kubernetes clusters for Flux `source-controller` versions and permissions that allow tenants to create/update `Bucket` or `GitRepository` resources.
5. Treat Flux findings as **controller-pod filesystem boundary** proofs, not cluster workload tampering, because digest verification can prevent manipulated artifacts from reaching downstream controllers.

## Replayable validation boundaries

### DbGate runner code-generation canary

Keep the proof marker-only. Do not run arbitrary OS commands against production systems.

1. Stand up a lab DbGate instance matching the assessed version and authentication mode.
2. Create a low-privileged account that should not have shell-script or administrative runner privileges.
3. Send `/runners/load-reader` or `/runners/start` JSON-runner requests where the injected JavaScript writes only an inert marker to a controlled temp path or performs a harmless `process.version`/environment-shape read in the lab.
4. Vulnerable result: the generated runner executes the injected JavaScript despite the account lacking shell-runner permission or despite `require = null` hardening.
5. Capture the endpoint, account role, runner feature state, sanitized request shape, generated error/output marker, container/process user, and DbGate version. Redact real connection strings and database credentials.

### DbGate Zip Slip file-write canary

Use a disposable container or VM; never write cron, SSH, shell profile, or service files on shared infrastructure.

1. Create a ZIP with a traversal entry targeting a harmless lab-only marker path such as `/tmp/skillz-dbgate-zip-slip-marker` or a controlled mounted scratch directory.
2. Upload the ZIP through DbGate's upload/archive workflow, then trigger archive unzip.
3. Vulnerable result: the marker file appears outside the archive extraction directory.
4. Capture the ZIP entry name, archive API sequence, resolved marker path, file owner, authentication mode, and version. Do not include payloads that establish persistence or shells.

### Sync-in IPv4-mapped IPv6 SSRF proof

1. Place a controlled canary HTTP listener on a loopback or RFC1918 address reachable only from the Sync-in host.
2. Submit the URL download feature a URL that resolves/connects as an IPv4-mapped IPv6 address for the private destination, such as a lab hostname resolving to `::ffff:127.0.0.1` or `::ffff:10.0.0.5`.
3. Baseline-test a normal private IPv4 URL and confirm it is blocked.
4. Vulnerable result: the mapped-IPv6 request reaches the canary listener while the plain private IPv4 request is blocked.
5. Capture DNS record, requested URL, observed `remoteAddress` form if logged, blocked baseline, canary hit, and version. Do not request cloud metadata or internal production admin paths.

### Flux source-controller path-boundary proof

1. In a lab cluster, grant a test user only the same `Bucket` or `GitRepository` privileges found in scope.
2. For the bucket path, control an object key or archive member that includes traversal and points to a scratch marker under the source-controller pod's writable filesystem.
3. For sparse-checkout probing on v1.6.0+, create a `GitRepository` with entries that should be rejected as traversal or absolute paths and observe whether status reveals path existence.
4. Vulnerable result: source-controller writes the marker outside the reconciliation workspace, or status feedback distinguishes existing from missing controller-pod paths.
5. Capture controller version, Kubernetes RBAC, resource YAML with marker-only paths, status messages, and pod-local marker evidence. Do not target secrets, service-account tokens, or production controller files.

## Reporting heuristics

- Frame DbGate findings as **string-to-code generation boundary failures in admin tooling**. Strong evidence compares denied shell-script capability with successful JSON/load-reader code execution by the same low-privileged account.
- Frame DbGate archive findings as **archive extraction path containment failure**. Marker file write outside the intended extraction root is enough; avoid persistence payloads.
- Frame Sync-in findings as **SSRF canonicalization mismatch**. Show plain IPv4 blocked and IPv4-mapped IPv6 allowed against the same controlled private canary.
- Frame Flux findings as **GitOps controller filesystem boundary**. Separate bucket-write impact from sparse-checkout existence probing and note digest-verification limits.

## Sources

- GitHub Advisory Database: [GHSA-wm5r-5qp3-5vxf / CVE-2026-47670](https://github.com/advisories/GHSA-wm5r-5qp3-5vxf)
- GitHub Advisory Database: [GHSA-hv83-ggc4-v385 / CVE-2026-48017](https://github.com/advisories/GHSA-hv83-ggc4-v385)
- GitHub Advisory Database: [GHSA-8v3q-9vmx-36vc / CVE-2026-47668](https://github.com/advisories/GHSA-8v3q-9vmx-36vc)
- GitHub Advisory Database: [GHSA-h535-j5hr-mv56 / CVE-2026-47669](https://github.com/advisories/GHSA-h535-j5hr-mv56)
- GitHub Advisory Database: [GHSA-q4x5-8cj6-52wg / CVE-2026-47684](https://github.com/advisories/GHSA-q4x5-8cj6-52wg)
- GitHub Advisory Database: [GHSA-jjrm-hr5f-673x / CVE-2026-47680](https://github.com/advisories/GHSA-jjrm-hr5f-673x)
- DbGate advisories/source: <https://github.com/dbgate/dbgate/security/advisories> and <https://github.com/dbgate/dbgate>
- Sync-in Server advisories/source: <https://github.com/Sync-in/server/security/advisories> and <https://github.com/Sync-in/server>
- Flux source-controller advisories/source: <https://github.com/fluxcd/source-controller/security/advisories> and <https://github.com/fluxcd/source-controller>
