---
title: Building replayable target environments
---

# Building replayable target environments

Use this when an exploit-validation agent needs a real vulnerable target, a patched negative control, and enough instrumentation to prove what happened without teaching the shared orchestration code about every product it may encounter.

!!! warning "Authorized lab use only"
    Build and exercise target environments only for systems you own, disposable research targets, or assessments where you have explicit permission. Bind intentionally vulnerable services to loopback or an isolated lab network.

## Core design rule

Keep the orchestrator generic and put target-specific behavior in the persisted run directory.

The shared pipeline should know how to invoke a small runtime contract such as:

```text
build | up | probe | logs | down
```

The run directory should know:

- which vulnerable and patched artifacts to acquire;
- how to verify and unpack them;
- which databases, sidecars, seed data, and credentials are needed;
- how to decide that each target is ready;
- which harmless oracle demonstrates the vulnerable behavior;
- how to collect evidence and tear everything down.

Avoid adding production branches such as `if package == "wordpress"` or `if cve == "..."`. Product-specific branches accumulate quickly, couple unrelated runs to old assumptions, and make historical evidence harder to replay.

## Recommended run layout

```text
cves/<CVE-ID>/runs/<RUN-ID>/
├── cve.json
├── harness/
│   ├── target-environment.json
│   ├── SETUP.md
│   ├── agent-runtime.sh
│   ├── Dockerfile.vulnerable
│   ├── Dockerfile.patched
│   ├── docker-compose.yml
│   ├── setup-target.sh
│   └── evidence/
├── exploiter/
│   ├── poc.py
│   └── outcome.json
└── sources/                 # usually ignored; reconstructed from pinned inputs
```

Keep generated source trees and bulky images out of version control when they can be reconstructed. Commit the acquisition logic, immutable coordinates, checksums, setup contract, and evidence needed to audit the run.

## Define the target contract first

Write a machine-readable `target-environment.json` before building the stack. At minimum, record:

```json
{
  "cve_id": "CVE-YYYY-NNNNN",
  "target_class": "userland_service",
  "backend": "docker_compose",
  "runtime_driver": "harness/agent-runtime.sh",
  "safety_boundary": "loopback-only disposable targets",
  "targets": {
    "vulnerable": {
      "product": "Example Service",
      "version": "1.2.3",
      "url": "http://127.0.0.1:4100"
    },
    "patched": {
      "product": "Example Service",
      "version": "1.2.4",
      "url": "http://127.0.0.1:4101"
    }
  },
  "source_artifacts": {
    "vulnerable": {
      "url": "https://vendor.example/releases/1.2.3.tar.gz",
      "sha256": "<pinned digest>"
    },
    "patched": {
      "url": "https://vendor.example/releases/1.2.4.tar.gz",
      "sha256": "<pinned digest>"
    }
  },
  "oracle": {
    "probe": "exploiter/poc.py",
    "expected_vulnerable": "triggered=true",
    "expected_patched": "triggered=false"
  }
}
```

Do not label a target `docker_compose` merely because a generic Dockerfile can be emitted. If the required VM image, installer, firmware, browser revision, kernel, service dependency, or hardware interface is missing, record an honest blocked state such as `blocked_needs_artifact` or `backend_unavailable`.

## Make the runtime interface boring

A stable adapter lets the outer workflow remain target-agnostic:

```bash
bash harness/agent-runtime.sh build
bash harness/agent-runtime.sh up
bash harness/agent-runtime.sh probe
bash harness/agent-runtime.sh logs
bash harness/agent-runtime.sh down
```

Expected behavior:

- `build`: acquire verified inputs and construct both targets.
- `up`: start dependencies, initialize state, and wait for readiness.
- `probe`: execute the run-local, scope-bound proof and write structured output.
- `logs`: capture enough service, sidecar, and instrumentation output to explain the result.
- `down`: stop the stack and remove ephemeral resources according to the documented reset policy.

Every verb should return nonzero on failure. Do not print a success-shaped message after an ignored command failure.

Support the runtime actually present in the lab. If the environment may have the Docker Compose plugin, legacy `docker-compose`, privileged Docker, or only direct Docker, detect those paths explicitly. If no complete backend exists, stop with a blocked result rather than substituting a synthetic service.

## Pin and verify source material

For every vulnerable/patched pair:

1. Prefer official release archives, vendor containers, signed packages, or exact source revisions.
2. Record the original URL, version, revision, image digest, and SHA-256.
3. Verify integrity before extraction or execution.
4. Reject unsafe archive paths before unpacking.
5. Assert that an expected product marker exists after extraction.
6. Record the actual running version during provisioning.

Archive extraction must reject:

- absolute paths;
- `..` traversal components;
- symlink or hardlink entries that escape the destination;
- unexpected top-level layouts;
- checksum mismatches.

A successful download is not sufficient provenance. Preserve the digest observed during the run.

## Build a real negative control

A convincing target environment contains both:

- the exact affected version; and
- the fixed version or a narrowly patched candidate.

Keep configuration equivalent across both variants unless the fix itself changes configuration. The same setup routine, credentials, data, requests, and probe should exercise both targets.

Expected differential:

```text
vulnerable: triggered=true
patched:    triggered=false
```

If both trigger, the claimed fix is not demonstrated. If neither triggers, investigate harness reachability, setup, preconditions, and oracle quality before concluding that the advisory is wrong.

## Separate readiness from vulnerability proof

A health endpoint proves that a process answers. It does not prove that:

- installation completed;
- migrations or seed data loaded;
- the vulnerable route is registered;
- authentication state is correct;
- the intended code path executes;
- instrumentation is active.

Use layered provisioning checks:

1. process or container health;
2. service-level readiness;
3. expected product/version marker;
4. vulnerable-surface reachability;
5. harmless functional oracle.

Write those results to structured provisioning evidence for each target. Do not award exploit confidence merely because containers started successfully.

## Keep instrumentation run-local

Put target-specific canaries, plugins, preload libraries, seed scripts, test users, callback receivers, and log parsers under the run directory.

Good instrumentation answers a narrow question, for example:

- Did request dispatch enter the guarded function twice?
- Did a deserializer instantiate the controlled type?
- Did the server make an outbound request carrying the run token?
- Did a candidate file write remain inside the disposable container?

Instrumentation can establish a boundary crossing, but it may not establish the entire exploit chain. Label evidence precisely:

- **Readiness evidence:** the target is alive and configured.
- **Boundary evidence:** the controlled input reached a security-relevant sink or guard.
- **Impact evidence:** the authorized lab demonstrated the claimed privilege, read, write, or execution result.
- **Patched evidence:** the same probe was blocked by the fixed target.

Do not translate an old boundary-only result into a high-confidence full exploit verdict after schemas or judging rules change. Preserve the original artifact and state its limitations.

## Enforce the operational safety boundary

For disposable local web targets:

- publish ports as `127.0.0.1:<port>:<container-port>`, never wildcard host bindings;
- hardcode loopback URLs in executable PoCs;
- do not let arguments, environment variables, stdin, or fetched configuration replace the host;
- use synthetic credentials and per-run canaries;
- avoid production tokens, third-party callback hosts, cloud metadata services, and shared infrastructure;
- make teardown explicit and verify no listeners or containers remain.

For multi-service chains, use an isolated per-run network and expose only the operator-facing target ports. Internal databases and sidecars usually need no host binding.

## Evidence package

A reviewable run should preserve:

- vulnerable and patched version proof;
- source and image digests;
- setup/provisioning results;
- exact probe input or executable PoC;
- structured vulnerable and patched outcomes;
- relevant target and sidecar logs;
- cleanup result;
- known limitations;
- hashes for any copied or normalized evidence.

If an artifact is edited only to normalize an identifier or redact a secret, preserve that fact and publish the hash of the normalized copy. Never silently rewrite historical evidence to fit a newer report schema.

## Common failure patterns

### Target logic leaked into the orchestrator

Symptom: shared source grows branches for individual package names, CVEs, ports, or setup commands.

Fix: move those details into `agent-runtime.sh`, `target-environment.json`, and run-local setup files. Add a generic adapter only when several targets share a stable ecosystem-level contract.

### Generic containers mistaken for real targets

Symptom: the harness builds, but it serves a placeholder health endpoint rather than the affected product.

Fix: require product/version proof and a functional oracle before marking the target servable.

### Stale mutable inputs

Symptom: yesterday's PoC worked, but today's rebuild silently pulled a patched image or dependency.

Fix: pin versions and digests, rebuild from clean state, and run the reference probe before agent evaluation.

### Evidence overclaims impact

Symptom: a canary confirms function reachability and the report calls it remote code execution.

Fix: separate boundary evidence from impact evidence and require a distinct, controlled impact proof.

### Teardown is not part of the contract

Symptom: occupied ports, contaminated volumes, or old credentials affect later runs.

Fix: make `down` and reset semantics first-class, then verify post-run state.

## Verification checklist

Before publishing or comparing a run:

- [ ] Vulnerable and patched versions are exact and recorded at runtime.
- [ ] Source archives, revisions, and images are immutable or hash-pinned.
- [ ] Archive extraction rejects traversal and link escapes.
- [ ] Product-specific behavior exists only in the run-local environment.
- [ ] Required runtime verbs return meaningful exit codes.
- [ ] All host bindings are loopback-only or confined to an authorized isolated range.
- [ ] Executable PoCs cannot redirect themselves to arbitrary hosts.
- [ ] Readiness, boundary, impact, and patched evidence are distinguished.
- [ ] The same probe runs against both variants.
- [ ] Logs and structured outcomes explain both positive and negative controls.
- [ ] Teardown leaves no target listeners or containers behind.
- [ ] Generated sources and secrets are not accidentally staged.
- [ ] JSON, YAML, shell, and language-specific syntax checks pass.
- [ ] Repository tests and documentation builds pass.

## Related guidance

- [Agentic DAST benchmark validation](agentic-dast-benchmark-validation.md)
- [CVE Reversing](cve-reversing-web-vulnerabilities.md)
- Docker Compose networking: https://docs.docker.com/compose/how-tos/networking/
- Docker published-port behavior: https://docs.docker.com/engine/network/port-publishing/
- Python `zipfile` extraction warnings: https://docs.python.org/3/library/zipfile.html
