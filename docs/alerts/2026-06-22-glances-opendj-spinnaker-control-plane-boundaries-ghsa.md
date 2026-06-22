# Glances, OpenDJ, and Spinnaker control-plane boundary checks

Source: hourly offensive-security scan, 2026-06-22. Primary entries: GitHub advisories [GHSA-v5r2-qh84-fjx5](https://github.com/advisories/GHSA-v5r2-qh84-fjx5) / CVE-2026-46606, [GHSA-43x2-g84q-fmqx](https://github.com/advisories/GHSA-43x2-g84q-fmqx) / CVE-2026-46495, and [GHSA-c8q4-9h32-2ww8](https://github.com/advisories/GHSA-c8q4-9h32-2ww8) / CVE-2026-44795.

This batch is durable because each advisory exposes a reusable operator workflow around privileged control planes: virtualization inventory names crossing into command construction, directory-server monitoring interfaces deserializing unauthenticated network input, and deployment pipeline YAML crossing into unsafe Java object loading.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-v5r2-qh84-fjx5](https://github.com/advisories/GHSA-v5r2-qh84-fjx5) / CVE-2026-46606 | Glances KVM/QEMU VM monitoring | VM domain names parsed from `virsh list --all` were interpolated into command templates processed by Glances' `secure_popen()` helper | Hypervisor monitoring reviews should include attacker-controlled inventory labels, not just HTTP/API parameters; prove with inert VM names and command-construction evidence in an approved lab. |
| [GHSA-43x2-g84q-fmqx](https://github.com/advisories/GHSA-43x2-g84q-fmqx) / CVE-2026-46495 | OpenDJ JMX RMI connection handler | unauthenticated bytes on the JMX RMI listener could reach Java deserialization before authentication | Directory and identity infrastructure assessments should enumerate exposed management listeners and validate whether monitoring-only ports deserialize pre-auth input. |
| [GHSA-c8q4-9h32-2ww8](https://github.com/advisories/GHSA-c8q4-9h32-2ww8) / CVE-2026-44795 | Spinnaker CloudFormation deployment / CloudFoundry baking | YAML supplied to deployment/baking workflows could bypass safe deserialization and load Java classes | CI/CD control-plane tests should treat deployment descriptors, bake manifests, and pipeline artifacts as code-loading surfaces when they are parsed by privileged services. |

Adjacent [GHSA-7cfq-5mhv-jrp9](https://github.com/advisories/GHSA-7cfq-5mhv-jrp9) was processed but not promoted because the public detail is an unprivileged container crash of an Inspektor Gadget USDT note parser and the advisory states no shipped gadget is affected. Revisit only if a future writeup provides a non-availability boundary such as host data disclosure, privilege crossing, or a reusable parser-fuzzing workflow.

## Operator triage

1. **Identify who controls the input.** VM names may be set by tenant admins or compromised orchestration paths; Spinnaker YAML may be contributed through repos, templates, or pipeline parameters; JMX RMI may be reachable only from monitoring networks.
2. **Separate management-plane reachability from application reachability.** These issues often sit on hypervisor hosts, LDAP/identity nodes, and CI/CD services that do not share the public web tier.
3. **Use canary-only proofs.** VM labels, lab JMX listeners, disposable directory servers, and synthetic pipeline descriptors are enough. Do not run payloads that alter host state, dump directory data, or execute commands in shared deployment systems.
4. **Record preconditions.** Include Glances run user, libvirt permissions, OpenDJ JMX handler state/port, Java version/classpath constraints, Spinnaker feature path, and whether CloudFormation or CloudFoundry baking is enabled.
5. **Prefer construction and callback evidence over impact escalation.** A logged command split, harmless local marker in a disposable VM lab, JMX handshake/deserialization reachability in a lab, or rejected/patched YAML comparison is safer and clearer than demonstrating broad RCE.

## Replayable validation boundaries

### Glances VM-name command-construction harness

- Preconditions: written approval for a disposable KVM/QEMU host or nested-virtualization lab, permission to create/rename VMs, and a Glances instance configured with the VM plugin.
- Create baseline VM names and one harmless canary name containing only an inert marker designed to show command-token interpretation in logs or a temporary lab output path.
- Run Glances as the same user and configuration used in scope, then capture `virsh` command construction, process arguments, or marker-only output from a temp directory.
- Do not run destructive shell operators, write outside temporary lab paths, alter production VM definitions, or target hosts where Glances runs as root unless the environment is disposable.
- Negative controls: patched Glances version, domain names passed as argument arrays rather than split command strings, strict libvirt naming validation, and Glances running with least privilege.

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

- Lead with the boundary: **VM inventory label to command runner**, **JMX RMI network bytes to Java deserialization before auth**, or **deployment YAML to privileged Java class loading**.
- Include reachability and role context: who can rename VMs, who can submit pipeline descriptors, which networks can reach JMX, and what OS/service account executes the affected component.
- Keep evidence non-sensitive: canary names, temp paths, lab listener logs, parser traces, version matrices, and patched-vs-vulnerable comparisons.
