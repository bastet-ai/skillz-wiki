# ActiveMQ Jolokia, Flink operator `jarURI`, and WebLogic middleware boundary batch

Sources: GitHub Security Advisories / NVD entries published or updated 2026-06-01: [GHSA-hg6c-8mvr-jqc9](https://github.com/advisories/GHSA-hg6c-8mvr-jqc9) / CVE-2026-42588, [GHSA-99qx-5qqr-4j95](https://github.com/advisories/GHSA-99qx-5qqr-4j95) / CVE-2026-49157, [GHSA-cpw7-g3p5-qrfq](https://github.com/advisories/GHSA-cpw7-g3p5-qrfq) / CVE-2026-46605, and [GHSA-rj6x-mg28-wf4x](https://github.com/advisories/GHSA-rj6x-mg28-wf4x) / CVE-2026-40564. CISA KEV catalog `2026.06.01` also added [CVE-2024-21182](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for Oracle WebLogic Server T3/IIOP compromise risk.

This batch is durable because the items all map to reusable operator checks for middleware control planes: exposed Jolokia/JMX management bridges, low-privilege web-console accounts that can reach broker admin operations, Kubernetes custom resources that dereference operator-controlled URIs, and internet-reachable Java middleware protocols.

## What changed

- **ActiveMQ Jolokia code-generation path** — Apache ActiveMQ Classic before `5.19.7` and `6.0.0` through before `6.2.6` exposes `/api/jolokia/` on the web console. The advisory describes default Jolokia policy permitting `exec` operations on `org.apache.activemq:*` MBeans, including `BrokerService.addNetworkConnector(String)`. A crafted discovery URI can reach the VM transport `brokerConfig` path and load a Spring XML application context, creating a code-execution boundary in the broker JVM.
- **ActiveMQ non-admin Jolokia management operations** — affected defaults grant non-admin web-console accounts access to broker management operations such as `addQueue` and `removeQueue`, turning a low-privilege login into broker-administration capability.
- **ActiveMQ destination-removal authorization drift** — authenticated connections can remove existing destinations despite intended permission boundaries, creating a queue/topic integrity and availability primitive that is useful to test when message-broker roles are in scope.
- **Flink Kubernetes Operator `jarURI` SSRF/file-read** — affected operator versions `1.3.0` through before `1.15.0` do not constrain `FlinkSessionJob.spec.job.jarURI` to user-owned files or approved addresses. A user with custom-resource create rights can point the operator at local files, internal HTTP(S) targets, link-local addresses, or alternate Flink filesystem backends.
- **WebLogic T3/IIOP KEV exposure** — CISA added CVE-2024-21182 for Oracle WebLogic Server compromise via network access to T3/IIOP. Public details are sparse, so treat it as a recon and exposure-prioritization signal rather than a standalone proof-of-concept recipe.

## Operator triage

1. **Prioritize management planes over application ports:** ActiveMQ web consoles, Jolokia endpoints, Kubernetes operators, and WebLogic T3/IIOP listeners are often reachable only after VPN, SSO, or internal pivoting. Findings are stronger when you prove the management plane was not intended for the tested role or network zone.
2. **Separate read-only discovery from mutation:** first prove endpoint reachability, version, principal, and visible MBean/CRD surface. Only perform queue creation/removal, connector changes, or CR submission in an explicitly authorized lab or disposable tenant.
3. **Use canaries for all callbacks:** SSRF, jar fetch, and protocol exposure checks should call an operator-controlled canary endpoint with a unique token. Do not target cloud metadata, real internal services, or production broker destinations unless the rules of engagement explicitly allow it.
4. **Report the invariant, not only the CVE:** the durable issue is “low-privileged principal can invoke admin control-plane operation” or “operator pod dereferences attacker-chosen URI,” which generalizes beyond the exact version.

## Recon and validation boundaries

### ActiveMQ web-console and Jolokia reachability

Use this only against systems in scope. The first pass is read-only.

```bash
# Common ActiveMQ web-console paths.
httpx -silent -status-code -title -path /admin/,/api/jolokia/version,/api/jolokia/list -l activemq-candidates.txt

# If credentials are authorized, verify the principal and visible Jolokia surface.
curl -sk -u 'lowpriv:REDACTED' \
  'https://broker.example.test/api/jolokia/version'

curl -sk -u 'lowpriv:REDACTED' \
  'https://broker.example.test/api/jolokia/list/org.apache.activemq'
```

High-signal evidence:

- `/api/jolokia/` is reachable from a network zone or principal that should not manage the broker.
- `org.apache.activemq` MBeans are visible to a non-admin account.
- `exec` operations for broker service or destination management appear in the Jolokia `list` output.

Avoid calling `exec` methods during initial recon. If the program authorizes lab mutation, use a disposable broker, destination, and canary names such as `skillz_canary_<case_id>`.

### ActiveMQ low-privilege management-operation check

In a lab or disposable broker only:

1. Create or obtain a non-admin web-console account matching the target role under test.
2. Confirm the UI does not expose the admin operation or that policy says the role should not manage broker destinations/connectors.
3. Through Jolokia, test a harmless broker operation against a disposable queue name. Prefer an operation that can be fully reverted, such as create/list/remove of `skillz_canary_<case_id>`.
4. A vulnerable result is successful queue/connector management by the low-privilege principal, or successful destination removal that bypasses expected authorization.

Evidence to capture: authenticated role, endpoint path, MBean operation name, canary destination name, response status/body, and before/after queue listing. Do not disrupt real destinations or live message flow.

### ActiveMQ connector/RCE boundary check without executing code

For CVE-2026-42588, avoid payloads that execute commands. The safe validation boundary is to prove the dangerous preconditions:

- affected ActiveMQ version range;
- authenticated access to `/api/jolokia/`;
- `exec` permission on `org.apache.activemq` MBeans;
- reachability of `BrokerService.addNetworkConnector(String)` or equivalent connector-management operations;
- ability to supply a controlled connector/discovery URI in a lab without command execution.

If a customer requires full exploit confirmation, do it only in an isolated lab broker and use a benign canary callback or no-op bean, never `Runtime.exec()` on production.

### Flink Kubernetes Operator `jarURI` SSRF/file-read check

Prerequisite: the tested principal is explicitly allowed to create Flink custom resources in the target namespace.

```bash
# Discover the CRD and operator version/surface.
kubectl api-resources | grep -i 'flink\|flinksessionjob'
kubectl get deploy -A | grep -i flink
kubectl get crd | grep -i flink
```

Safe callback test pattern:

1. Stand up an HTTPS canary listener you control, with a path like `/flink-jaruri/<case_id>.jar`.
2. Submit a minimal `FlinkSessionJob` in a disposable namespace or lab cluster whose `spec.job.jarURI` points to that canary URL.
3. A vulnerable result is an operator-initiated HTTP request to the canary from the operator pod or cluster egress path, especially when policy says arbitrary HTTP(S) or link-local targets should not be dereferenced.
4. For file-read claims, use only benign, non-secret lab files and prove that content can be surfaced through the submitted job. Do not read service-account tokens, cloud metadata, or production files.

Report the CR manifest, namespace, requesting Kubernetes identity, canary hit metadata, and whether scheme/host/IP-range checks were absent.

### WebLogic T3/IIOP KEV exposure check

Because the KEV entry does not provide a public exploit workflow, keep this to exposure discovery and version/scope prioritization.

```bash
# Identify WebLogic HTTP consoles and likely T3/IIOP listeners.
httpx -silent -status-code -title -path /console/login/LoginForm.jsp,/console/ -l weblogic-candidates.txt
nmap -Pn -sT -p 7001,7002,8001,9001 --open --script=banner -iL weblogic-hosts.txt
```

High-signal evidence:

- WebLogic console or protocol ports are reachable from an unintended zone.
- Banner, HTTP title, certificate, or app response ties the host to Oracle WebLogic Server.
- T3/IIOP exposure aligns with a vulnerable version or an asset class already accepted as high risk by the rules of engagement.

Do not publish or run unauthenticated WebLogic exploit payloads from a sparse KEV note. Treat the item as an input for target prioritization, not as proof by itself.

## Reporting heuristics

- For ActiveMQ, include the exact account class tested, the Jolokia path, the MBean domain, and the allowed operation. The strongest finding is a role/control-plane mismatch.
- For broker mutation, prove reversibility with a disposable queue/topic and before/after listings. Avoid evidence from production queues.
- For Flink, include the Kubernetes RBAC verb/resource that permits CR creation and the network/file boundary crossed by `jarURI` resolution.
- For WebLogic, separate “exposed suspected middleware” from “confirmed vulnerable WebLogic.” Do not overstate KEV exposure without version or vendor evidence.

## Notes on skipped and unchanged sources

- GitHub Advisory Database also listed several generic CMS, kernel, WLAN, and plugin advisories that did not add durable operator guidance beyond existing XSS/SQLi/arbitrary-file-delete patterns, so they were processed but not promoted.
- CISA KEV changed from catalog `2026.05.29` to `2026.06.01` for CVE-2024-21182; the prior PAN-OS CVE-2026-0257 item remains already reflected.
- PortSwigger stayed on the Top 10 web hacking techniques of 2025; ProjectDiscovery stayed on already-covered Neo/Nuclei/DAST material; GitHub Security Blog stayed GHES signing-key rotation / IR-oriented; Trail of Bits stayed on older zizmor/fuzzing material; Disclosed stayed lander-only.
