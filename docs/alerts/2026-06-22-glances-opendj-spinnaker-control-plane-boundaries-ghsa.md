# Glances, OpenDJ, and Spinnaker control-plane boundary checks

Source: hourly offensive-security scan, 2026-06-22. Primary entries: GitHub advisories [GHSA-v5r2-qh84-fjx5](https://github.com/advisories/GHSA-v5r2-qh84-fjx5) / CVE-2026-46606, [GHSA-43x2-g84q-fmqx](https://github.com/advisories/GHSA-43x2-g84q-fmqx) / CVE-2026-46495, and [GHSA-c8q4-9h32-2ww8](https://github.com/advisories/GHSA-c8q4-9h32-2ww8) / CVE-2026-44795. Late same-hour updates added [GHSA-w856-8p3r-p338](https://github.com/advisories/GHSA-w856-8p3r-p338) / CVE-2026-46611, [GHSA-87qc-fj39-wccr](https://github.com/advisories/GHSA-87qc-fj39-wccr) / CVE-2026-46608, and [GHSA-3f62-qv96-4p78](https://github.com/advisories/GHSA-3f62-qv96-4p78) / CVE-2026-46700.

This batch is durable because each advisory exposes a reusable operator workflow around privileged control planes: virtualization inventory names crossing into command construction, observability browser trust reaching system-monitoring datasets, directory-server monitoring interfaces deserializing unauthenticated network input, deployment pipeline YAML crossing into unsafe Java object loading, and finance-app sync secrets leaking through role-check drift.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-v5r2-qh84-fjx5](https://github.com/advisories/GHSA-v5r2-qh84-fjx5) / CVE-2026-46606 | Glances KVM/QEMU VM monitoring | VM domain names parsed from `virsh list --all` were interpolated into command templates processed by Glances' `secure_popen()` helper | Hypervisor monitoring reviews should include attacker-controlled inventory labels, not just HTTP/API parameters; prove with inert VM names and command-construction evidence in an approved lab. |
| [GHSA-43x2-g84q-fmqx](https://github.com/advisories/GHSA-43x2-g84q-fmqx) / CVE-2026-46495 | OpenDJ JMX RMI connection handler | unauthenticated bytes on the JMX RMI listener could reach Java deserialization before authentication | Directory and identity infrastructure assessments should enumerate exposed management listeners and validate whether monitoring-only ports deserialize pre-auth input. |
| [GHSA-c8q4-9h32-2ww8](https://github.com/advisories/GHSA-c8q4-9h32-2ww8) / CVE-2026-44795 | Spinnaker CloudFormation deployment / CloudFoundry baking | YAML supplied to deployment/baking workflows could bypass safe deserialization and load Java classes | CI/CD control-plane tests should treat deployment descriptors, bake manifests, and pipeline artifacts as code-loading surfaces when they are parsed by privileged services. |
| [GHSA-w856-8p3r-p338](https://github.com/advisories/GHSA-w856-8p3r-p338) / CVE-2026-46611 | Glances XML-RPC server (`glances -s`) | XML-RPC HTTP requests did not validate `Host`, so a browser could be steered through DNS rebinding toward a local/management Glances server | Observability tooling reviews should test all exposed protocol backends, not only the patched REST/WebUI path; prove with owned rebinding domains and harmless dataset/version requests. |
| [GHSA-87qc-fj39-wccr](https://github.com/advisories/GHSA-87qc-fj39-wccr) / CVE-2026-46608 | Glances XML-RPC CORS handling | multi-origin `cors_origins` configurations silently fell back to `Access-Control-Allow-Origin: *` | Browser-origin validation should include multi-entry allowlists and patched-path parity checks across REST, MCP, and XML-RPC listeners. |
| [GHSA-3f62-qv96-4p78](https://github.com/advisories/GHSA-3f62-qv96-4p78) / CVE-2026-46700 | `@actual-app/sync-server` OpenID multi-user deployments | `GET /secret/:name` required a session but not admin role, allowing non-admin users to enumerate which bank-sync integration secrets exist | SaaS/self-hosted finance app tests should compare sibling secret-management endpoints for role asymmetry and prove only existence or absence of synthetic secret names. |

Adjacent [GHSA-7cfq-5mhv-jrp9](https://github.com/advisories/GHSA-7cfq-5mhv-jrp9) was processed but not promoted because the public detail is an unprivileged container crash of an Inspektor Gadget USDT note parser and the advisory states no shipped gadget is affected. [GHSA-7gh7-258j-4mpq](https://github.com/advisories/GHSA-7gh7-258j-4mpq) was also processed without promotion because Actual CLI CSV formula injection is a useful report-hygiene finding but does not add a new operator workflow beyond existing CSV/export formula checks. Revisit only if future detail ties either item to a non-availability boundary, privilege crossing, or reusable exploit-path validation pattern.

## Operator triage

1. **Identify who controls the input.** VM names may be set by tenant admins or compromised orchestration paths; Glances XML-RPC may be reachable from browsers on operator workstations or internal dashboards; Actual sync-server secret names may be guessable by any authenticated non-admin OpenID user; Spinnaker YAML may be contributed through repos, templates, or pipeline parameters; JMX RMI may be reachable only from monitoring networks.
2. **Separate management-plane reachability from application reachability.** These issues often sit on hypervisor hosts, observability daemons, finance sync services, LDAP/identity nodes, and CI/CD services that do not share the public web tier.
3. **Use canary-only proofs.** VM labels, owned browser origins, lab XML-RPC requests, synthetic Actual secret names, lab JMX listeners, disposable directory servers, and synthetic pipeline descriptors are enough. Do not run payloads that alter host state, dump monitoring datasets, enumerate real bank-sync credentials, dump directory data, or execute commands in shared deployment systems.
4. **Record preconditions.** Include Glances run user, libvirt permissions, XML-RPC bind address and `cors_origins`, Actual auth mode and user role, OpenDJ JMX handler state/port, Java version/classpath constraints, Spinnaker feature path, and whether CloudFormation or CloudFoundry baking is enabled.
5. **Prefer construction and callback evidence over impact escalation.** A logged command split, harmless local marker in a disposable VM lab, browser-origin allow/deny tables, positive/negative synthetic secret-name probes, JMX handshake/deserialization reachability in a lab, or rejected/patched YAML comparison is safer and clearer than demonstrating broad RCE or secret access.

## Replayable validation boundaries

### Glances VM-name command-construction harness

- Preconditions: written approval for a disposable KVM/QEMU host or nested-virtualization lab, permission to create/rename VMs, and a Glances instance configured with the VM plugin.
- Create baseline VM names and one harmless canary name containing only an inert marker designed to show command-token interpretation in logs or a temporary lab output path.
- Run Glances as the same user and configuration used in scope, then capture `virsh` command construction, process arguments, or marker-only output from a temp directory.
- Do not run destructive shell operators, write outside temporary lab paths, alter production VM definitions, or target hosts where Glances runs as root unless the environment is disposable.
- Negative controls: patched Glances version, domain names passed as argument arrays rather than split command strings, strict libvirt naming validation, and Glances running with least privilege.

### Glances XML-RPC browser-trust harness

- Preconditions: scoped Glances XML-RPC server (`glances -s`) in a lab or customer-approved environment, an owned browser origin/domain, and approval to test browser-origin behavior against monitoring endpoints.
- Test `Host` handling separately from CORS: send baseline XML-RPC requests with the expected host, then an owned rebinding/alternate `Host` canary, and record whether the XML-RPC server accepts both.
- Test single-origin and multi-origin `cors_origins` configurations. Capture only headers and a harmless method/version or synthetic monitoring value; do not collect process lists, network peers, file-system paths, credentials, or full host telemetry from production systems.
- Negative controls: Glances 4.5.5+, XML-RPC disabled or bound to localhost/management VPN, strict `Host` validation, no wildcard CORS fallback for multi-origin lists, and browser access blocked by network segmentation.

### Actual sync-server secret-name authorization harness

- Preconditions: owned `@actual-app/sync-server` lab or explicit authorization for a self-hosted deployment, OpenID multi-user mode, one admin user, and one disposable non-admin user.
- As admin, create synthetic secret names only, for example `skillz_canary_simplefin_accessKey`, then attempt `GET /secret/:name` as the non-admin user for both existing and nonexistent canaries.
- Evidence should show role asymmetry and existence inference only: status codes, response-shape differences, and patched-vs-vulnerable comparisons. Never enumerate real integration names in production, retrieve secret values, or touch live bank-sync credentials.
- Negative controls: `@actual-app/sync-server` 26.6.0+, admin checks on both `GET` and `POST` secret routes, non-admin users receiving identical responses for existing and nonexistent names, and deployments without multi-user OpenID secret management.

### OpenDJ JMX RMI pre-auth deserialization harness

- Preconditions: an owned OpenDJ lab instance, explicit approval to test management ports, and confirmation whether the JMX connection handler is enabled.
- Enumerate configured JMX/RMI listeners from admin-approved configuration or scoped port scans. Avoid broad Internet scanning unless the engagement explicitly authorizes it.
- In the lab, send a harmless serialization canary that proves bytes are parsed before authentication, or compare vulnerable and patched versions with connection/log evidence only.
- Do not deploy public gadget chains, trigger command execution, read directory contents, capture credentials, or fuzz production identity servers.
- Negative controls: OpenDJ 5.1.1+, JMX disabled, listener bound to localhost/management VPN, authentication before object deserialization, and JVM serialization filters.

### Spinnaker YAML deserialization harness

- Preconditions: an isolated Spinnaker lab, disposable cloud/bake targets, and permission to run CloudFormation deployment or CloudFoundry baking workflows.
- Submit a baseline YAML descriptor and a canary descriptor that exercises type handling without creating cloud resources or invoking commands.
- Capture parser errors, class-resolution logs, or benign marker behavior that proves unsafe constructor reachability. Keep pipeline artifacts and screenshots free of cloud secrets.
- Do not deploy infrastructure, bake images, run system commands, or use production credentials while validating parser behavior.
- Negative controls: patched Spinnaker releases 2025.3.3, 2026.0.3, or 2025.4.4; feature disabled; YAML parsed with safe constructors only; pipeline templates restricted to trusted repositories.

## Reporting notes

- Lead with the boundary: **VM inventory label to command runner**, **browser origin/Host header to observability XML-RPC dataset**, **non-admin finance-app user to admin-managed secret-name oracle**, **JMX RMI network bytes to Java deserialization before auth**, or **deployment YAML to privileged Java class loading**.
- Include reachability and role context: who can rename VMs, which browsers/networks can reach Glances XML-RPC, who can authenticate to Actual as non-admin, who can submit pipeline descriptors, which networks can reach JMX, and what OS/service account executes the affected component.
- Keep evidence non-sensitive: canary names, temp paths, lab listener logs, CORS/Host decision tables, synthetic secret-name status differences, parser traces, version matrices, and patched-vs-vulnerable comparisons.

## June 23 Glances AMP command update

GitHub Advisory Database added [GHSA-3vwc-qwhc-3mj7](https://github.com/advisories/GHSA-3vwc-qwhc-3mj7) / CVE-2026-53925 for another Glances `secure_popen()` boundary: AMP command configuration could include shell redirection or chaining operators and reach arbitrary file write or command execution.

Operator value: this expands Glances testing beyond VM inventory names and browser-origin trust. Assessments should review **monitoring plugin configuration to command runner** paths, especially where low-privilege operators, config-management pipelines, or tenant-provided templates can influence AMP commands.

Safe validation boundaries:

1. Use a lab Glances instance with a disposable AMP config and a temporary output directory owned by the test user.
2. Compare a baseline AMP command with an inert canary containing redirection or a single benign chaining marker. Evidence should be command parsing, a temp-file marker, or rejection logs; do not run shell payloads that enumerate the host.
3. Confirm the run user and plugin enablement. Running Glances as root or with broad host mounts materially changes impact and should be called out as a precondition, not assumed.
4. Negative controls: AMP command arguments passed as arrays, shell metacharacters rejected before `secure_popen()`, and configs restricted to trusted administrators.

Reporting heuristic: title as **AMP command config to Glances command runner**, include the exact config source, service account, command line or parser trace, temp marker path, and patched-version rejection.

## July 24 OpenDJ proxy-identity and DSML URI follow-up

Two OpenDJ 5.1.2 fixes add distinct directory-server boundaries:

- [GHSA-p279-2cqp-84jg](https://github.com/advisories/GHSA-p279-2cqp-84jg): SASL PLAIN `authzid` accepted a different resolvable user when the authenticating account held `proxied-auth`, but omitted the target-scoped `mayProxy` ACI decision enforced by other proxy paths.
- [GHSA-68r5-9hpg-7qw9](https://github.com/advisories/GHSA-68r5-9hpg-7qw9): the unauthenticated DSMLv2 SOAP gateway dereferenced `xsd:anyURI` values, including local-file and outbound HTTP sources, before the fixed release disabled dereferencing by default and bounded the opt-in path.

For SASL, create a proxy account, one in-scope synthetic target, and one out-of-scope synthetic target. Compare PLAIN `dn:`/`u:` forms with RFC 4370, DIGEST-MD5, or GSSAPI controls, and preserve only the effective canary identity and access decision. Do not impersonate administrators or read directory data.

For DSML, use an owned callback and a benign file created under a lab temp directory. Send one add/modify request containing the canary URI and record callback or marker-byte handling; never point at metadata, internal production services, directory configuration, or credentials. Report **DSML value coercion -> URI dereference -> owned network/file canary**, and keep the unbounded-read availability behavior out of the proof.

## September 22 Checkmk follow-up: GUI-hidden secrets served by the API + newline injection into the query protocol

Two Checkmk advisories ([GHSA-xwvr-5xw4-qv5w](https://github.com/advisories/GHSA-xwvr-5xw4-qv5w) / [CVE-2026-92882](https://nvd.nist.gov/vuln/detail/CVE-2026-92882), and [GHSA-v742-5hjw-gqcp](https://github.com/advisories/GHSA-v742-5hjw-gqcp) / [CVE-2026-90990](https://nvd.nist.gov/vuln/detail/CVE-2026-90990)) extend monitoring-plane testing in two directions:

- **API-read parity for GUI-hidden secrets.** Host and folder configuration REST endpoints returned stored SNMP community strings, SNMPv3 auth/privacy passphrases, and IPMI passwords **in cleartext GET responses** to any authenticated user allowed to *view* host configuration — even though the setup GUI never displays these values. Audit rule for every admin/console product with both a GUI and a REST API: the GUI's field-hiding is not an access control; as a low-privilege viewer, GET the same object through the API and diff which fields the GUI masks but the API serves. Sweep secret-shaped keys (`community`, `passphrase`, `password`, `secret`, `authkey`) in API responses; prove only with your own lab-configured fake credentials on a disposable host object.
- **Filter values crossing into protocol framing.** Monitoring host/service list APIs passed filter values into **Livestatus query headers** without newline neutralization, letting an authenticated user inject additional query headers to bypass object-visibility restrictions in count queries — an inference oracle over hosts/services outside their contact groups. This is the query-protocol sibling of the header-injection family: any UI/API parameter that becomes a *line* in a text-framed protocol (Livestatus, HTTP, SMTP, SIP, LDAP filters rendered as header lines) must be CRLF-free by enforcement, not convention. Test battery: append `\r\n<Header>: x` shaped inert markers to each filter/search/sort parameter and record the raw bytes toward the backend (patched socket recorder in a lab), plus a count-delta oracle comparing your contact group's totals with and without the injected header against synthetic rows you own. The count oracle is the reportable impact — infer existence/attributes of out-of-scope objects without ever reading their full rows.
- Both items also reinforce the monitoring-plane target map: a monitoring server aggregates credentials and inventory for the whole estate, so low-role viewer drift (this pair) escalates fast. Fingerprint the low-role API surface first, keep proofs inside two synthetic contact groups you created, and never dump live SNMP/IPMI credentials from a production site.
