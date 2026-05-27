# Agent, container, ICS, and CMS boundary batch (GHSA, 2026-05-27)

**Signal:** A follow-on May 27 GitHub Advisory batch adds replayable operator guidance around agent/AI tooling command boundaries, container guest-to-host escape validation, ICS algorithm override RCE, compliance-profile cache path traversal, and CMS/HMI authorization bypasses. The useful pattern is not “patch these packages”; it is where attacker-controlled project data, model/data artifacts, guest-root primitives, or low-privileged backend users cross into execution, host writes, or sensitive operational data.

Promoted items:

- `GHSA-g3vg-vx23-3858` / `CVE-2026-45725`: `compliance-trestle` remote OSCAL fetching writes HTTPS/SFTP cache files using unsanitized URL path components, allowing `../` traversal from a malicious OSCAL profile to attacker-controlled file writes outside `.trestle/cache`.
- `GHSA-2gv2-cffp-j227` / `CVE-2026-47243`: Kata Containers `runtime-rs` standalone `virtio-fs` can let guest root send raw FUSE requests to host `virtiofsd` and create host-root-owned symlinks outside the shared directory, enabling guest-root to host-root escape in affected configurations.
- `GHSA-vmwp-vh32-rj75` / `CVE-2026-46562` and `GHSA-2g95-6x5q-xjwj` / `CVE-2026-46621`: Yamcs algorithm overrides can execute OS commands through unsandboxed Nashorn JavaScript or Jython engines when a user can change mission-database algorithms; default guest/superuser configurations can make the JavaScript path reachable without a real login.
- `GHSA-m85w-whwh-qvfx` / `CVE-2026-31246`, `GHSA-g76p-4vg5-f4qh` / `CVE-2026-31236`, `GHSA-cgx8-qgvr-f7vf` / `CVE-2026-31245`, and `GHSA-gq6f-qwv9-rf4j` / `CVE-2026-31241`: agent/LLM tooling boundaries in GPT-Pilot, `llm`, and `mem0` where user/project-controlled command text, function snippets, or unauthenticated memory APIs affect execution or agent state.
- `GHSA-g82g-j283-hj97` / `CVE-2026-31235`, `GHSA-wcr3-gm9f-f87q` / `CVE-2026-31237`, and `GHSA-xp5q-5q7g-q26r` / `CVE-2026-31238`: ML pipeline deserialization boundaries in `imgaug` background workers and Ludwig prediction/serving flows via pickle-backed datasets or model weights.
- `GHSA-q3w6-q3hc-c5x6` / `CVE-2026-47717`: FUXA `1.3.0` guest-token behavior exposes `/api/project` data including scripts, device config, HMI views, alarms, and tag bindings without an explicit credential.
- `GHSA-jwcc-gv4m-93x6` / `CVE-2026-45704` and `GHSA-332x-r494-54fq` / `CVE-2026-45703`: Pimcore backend authorization drift lets low-privileged users retrieve unshared CustomReports or export document content without per-element view rights.

Use this only in authorized testing. Keep proofs in disposable labs, private model/data artifacts, local container hosts, test Yamcs/FUXA/Pimcore instances, or explicitly scoped staging environments. Do not publish malicious packages/models, attempt guest escapes on shared infrastructure, access OT/ICS data outside scope, or use recovered configuration data for follow-on intrusion.

## Operator checklist

### 1. OSCAL remote-reference cache traversal: `compliance-trestle`

Where to look:

- CI jobs, GRC automation, FedRAMP/OSCAL validation pipelines, and agent tasks that run `compliance-trestle` against externally supplied profiles or catalogs.
- Versions `>= 4.0.0, <= 4.0.2` and `< 3.12.2`.
- Workflows that fetch remote profile imports over HTTPS or SFTP and run with write access to workspaces, home directories, deployment repos, hooks, or cron-like paths.

Safe validation path:

1. Confirm that untrusted OSCAL content can introduce a remote URL that `HTTPSFetcher` or `SFTPFetcher` resolves.
2. In a disposable workspace, serve a harmless remote profile URL whose path contains traversal and a unique marker body.
3. Run the normal `trestle` fetch/import path and prove the marker lands outside the intended cache directory.
4. Stop at marker-file creation unless explicit scope authorizes impact proof. Do not target shell startup files, SSH keys, cron paths, CI hooks, or repo automation outside a lab.

Reporting heuristic: strong reports show **attacker-controlled OSCAL references become arbitrary local writes under the automation user**. Include the vulnerable version, profile/import path, resolved cache path, write location, process user, and what sensitive directories are reachable in the real deployment.

### 2. Kata `runtime-rs` virtio-fs guest-to-host escape

Where to look:

- Kata Containers deployments using `runtime-rs`, `shared_fs = "virtio-fs"`, standalone host `virtiofsd`, `rootless = false`, and QEMU or Cloud Hypervisor.
- Multi-tenant container platforms where an attacker can become root inside a Kata guest VM.
- Hosts with `virtiofsd` launched with weak sandboxing such as `--sandbox none --seccomp none`.

Safe validation path:

1. Reproduce only on a dedicated lab host or program-approved staging node. Guest-escape tests are high-impact even when the primitive is a symlink.
2. Confirm config from the host side: runtime class, `runtime-rs` version/commit, `virtio-fs`, rootless setting, and `virtiofsd` command line.
3. From guest root, use a benign FUSE request proof that creates a uniquely named symlink in a harmless host-owned test directory selected for the lab.
4. Avoid `/etc/cron.d`, host SSH paths, systemd units, kubelet paths, or other persistence/execution locations unless the scope explicitly authorizes full escape validation.

Reporting heuristic: high-value reports prove **guest root can affect host-root filesystem state outside the shared directory**. Include the host runtime configuration, guest privilege requirement, exact host path touched in lab, and why tenant isolation is crossed.

### 3. Yamcs mission-database algorithm override RCE

Where to look:

- Yamcs `< 5.12.7` instances with Mission Database editing enabled.
- Default or demo deployments where `security.yaml` is absent and the built-in guest user has broad privileges.
- Existing JavaScript `CustomAlgorithm` definitions for the Nashorn path or Python/Jython algorithms for the Jython path.
- Users or API tokens with `SystemPrivilege.ChangeMissionDatabase`.

Safe validation path:

1. Enumerate whether the target exposes the MDB API and which algorithms exist. Prefer read-only evidence first.
2. In a lab, PATCH a disposable algorithm to run a harmless command such as writing a marker file or calling a controlled canary URL.
3. For real programs, avoid changing production flight/telemetry algorithms. If staging is unavailable, report the privilege model, affected version, algorithm language, and source-level reachability rather than executing code.
4. Capture whether the path is authenticated, guest-reachable, or restricted to a high-privilege role; that distinction drives severity.

Reporting heuristic: frame this as **mission-database edit privilege crossing into JVM/OS command execution**. Strong evidence includes Yamcs version, security configuration, algorithm language, API route, privilege required, and a lab marker proof.

### 4. Agent and LLM tool command/state boundaries

Where to look:

- GPT-Pilot `<= 0.0.10` flows where a user, project file, prompt, issue text, or untrusted agent instruction can alter a confirmed shell command before `asyncio.create_subprocess_shell()` runs it.
- `llm <= 0.27.1` recipes, documentation, plugins, CI tasks, or agent-generated commands that include `--functions` snippets.
- `mem0ai <= 1.0.0` servers exposing unauthenticated `POST /memories` or `DELETE /memories` endpoints, especially where memories feed autonomous agents, retrieval-augmented actions, or decision workflows.

Safe validation path:

1. For command-execution tools, build a local harness that records command strings and proves only a benign marker command executes.
2. For `llm --functions`, prove that copied/generated function snippets are executable Python code, not inert configuration. Avoid distributing weaponized one-liners.
3. For `mem0`, use a canary memory entry and a scoped test user/run/agent ID. Confirm whether unauthenticated creation changes later retrieval or agent behavior; separately validate deletion only against disposable data.
4. Record who controls the input, whether a human confirmation screen is present, and whether the execution happens on a developer laptop, CI runner, or server-side agent worker.

Reporting heuristic: impactful reports show **untrusted project/prompt/API input crosses into tool execution or persistent agent memory**. Include the route from input to action, required interaction, execution user, environment secrets, and a non-destructive proof.

### 5. ML artifact deserialization in imgaug and Ludwig

Where to look:

- `imgaug <= 0.4.0` jobs using `BackgroundAugmenter` where queue inputs, augmentation scripts, or worker processes can be influenced across user/project boundaries.
- Ludwig `<= 0.10.4` prediction services that accept dataset file paths or uploaded `.pkl` files and call `predict()`.
- Ludwig serving workflows that load model weights from untrusted storage, user-supplied model bundles, or remotely configured paths without `weights_only=True`.

Safe validation path:

1. Reproduce in an isolated Python environment with a pickle payload that writes a marker file or emits a canary callback to your own listener.
2. For Ludwig predict paths, prove that file type inference reaches `pandas.read_pickle()` for a user-controlled `.pkl` dataset.
3. For Ludwig serve paths, prove that a model artifact is loaded through `torch.load()` with pickle semantics.
4. In shared ML platforms, stop at version/call-path/source-control evidence unless explicit RCE validation is authorized.

Reporting heuristic: strong reports demonstrate **model or dataset artifacts are treated as trusted code-bearing objects**. Include artifact source control, file extension/type detection, loader call path, package version, process user, and any mounted secrets/datasets.

### 6. FUXA project disclosure as chain support

Where to look:

- FUXA `1.3.0` instances, especially OT labs, staging HMIs, vendor demos, or exposed web HMIs with `secureEnabled: true`.
- `/api/project` responses available without a bearer token or cookie.
- Environments where project data includes server-side script source, device endpoints, HMI SVGs, tag bindings, alarm rules, or Node-RED/FUXA integration details.

Safe validation path:

1. Send a minimal unauthenticated `GET /api/project` to a scoped instance.
2. If sensitive data appears, redact aggressively. Do not connect to devices, modify tags, or execute scripts.
3. Map only enough script/device/tag names to show operational impact and chain support for already authorized FUXA testing.
4. Pair with prior FUXA auth-bypass/RCE findings only when the program allows chained validation.

Reporting heuristic: present this as **guest-context access to operational project internals**. High-quality reports show the missing auth boundary, redacted sensitive fields, FUXA version, and how exposed scripts/device mappings support a realistic attack path.

### 7. Pimcore report and document export authorization drift

Where to look:

- Pimcore `<= 12.3.5` for CustomReports share bypass and `<= 12.3.6` for WordExport document export bypass.
- Low-privileged backend accounts with generic `reports`, `reports_config`, or `word_export` feature permissions but no share/view rights for specific reports or documents.
- Admin routes that retrieve objects directly by report name or `type/id` rather than applying the same permission checks used by list views.

Safe validation path:

1. Create or request a low-privileged test backend user and a hidden report/document with a harmless marker string.
2. Confirm the marker is not visible through the normal UI/list flow.
3. Directly request the report detail or WordExport route and verify whether the marker is returned/exported.
4. Avoid exporting real sensitive content; use seeded marker objects whenever possible.

Reporting heuristic: strong reports show **feature-level permission is not equivalent to object-level authorization**. Include the denied list/UI evidence, direct endpoint response, object ID/name, assigned roles, and affected Pimcore version.

## Non-signal this hour

Reviewed but not promoted as standalone Skillz guidance:

- FUXA project disclosure and Pimcore report/export bypasses were promoted as chain-support and authorization-testing heuristics, not as destructive OT or data-exfiltration instructions.
- Several AI/ML package advisories from the May 12 publication window were promoted only where the May 27 update made them newly visible in the GitHub advisory stream and they provide reusable agent/model artifact boundary checks.
- CISA KEV remained catalog `2026.05.27`; the Nx Console, TanStack, Daemon Tools Lite, and LiteSpeed cPanel plugin entries were already reflected or did not add fresh Skillz operator guidance this pass.
- PortSwigger Research stayed on the Top 10 web hacking techniques of 2025.
- Trail of Bits stayed on the already-covered zizmor GitHub Actions static-analysis article.
- ProjectDiscovery `/blog/rss` stayed on already-covered Neo / Nuclei / DAST proof-loop material, while `/blog/rss.xml` still returned 404.
- GitHub Security Blog remained GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.

## Sources

- [compliance-trestle cache path traversal advisory (`GHSA-g3vg-vx23-3858`)](https://github.com/advisories/GHSA-g3vg-vx23-3858)
- [Kata `runtime-rs` virtio-fs guest escape advisory (`GHSA-2gv2-cffp-j227`)](https://github.com/advisories/GHSA-2gv2-cffp-j227)
- [Yamcs Nashorn algorithm override RCE advisory (`GHSA-vmwp-vh32-rj75`)](https://github.com/advisories/GHSA-vmwp-vh32-rj75)
- [Yamcs Jython algorithm code injection advisory (`GHSA-2g95-6x5q-xjwj`)](https://github.com/advisories/GHSA-2g95-6x5q-xjwj)
- [GPT-Pilot command injection advisory (`GHSA-m85w-whwh-qvfx`)](https://github.com/advisories/GHSA-m85w-whwh-qvfx)
- [`llm` CLI `--functions` code injection advisory (`GHSA-g76p-4vg5-f4qh`)](https://github.com/advisories/GHSA-g76p-4vg5-f4qh)
- [mem0 memory creation authorization advisory (`GHSA-cgx8-qgvr-f7vf`)](https://github.com/advisories/GHSA-cgx8-qgvr-f7vf)
- [mem0 memory deletion authorization advisory (`GHSA-gq6f-qwv9-rf4j`)](https://github.com/advisories/GHSA-gq6f-qwv9-rf4j)
- [imgaug BackgroundAugmenter deserialization advisory (`GHSA-g82g-j283-hj97`)](https://github.com/advisories/GHSA-g82g-j283-hj97)
- [Ludwig `predict()` deserialization advisory (`GHSA-wcr3-gm9f-f87q`)](https://github.com/advisories/GHSA-wcr3-gm9f-f87q)
- [Ludwig model serving deserialization advisory (`GHSA-xp5q-5q7g-q26r`)](https://github.com/advisories/GHSA-xp5q-5q7g-q26r)
- [FUXA project disclosure advisory (`GHSA-q3w6-q3hc-c5x6`)](https://github.com/advisories/GHSA-q3w6-q3hc-c5x6)
- [Pimcore CustomReports share bypass advisory (`GHSA-jwcc-gv4m-93x6`)](https://github.com/advisories/GHSA-jwcc-gv4m-93x6)
- [Pimcore WordExport authorization bypass advisory (`GHSA-332x-r494-54fq`)](https://github.com/advisories/GHSA-332x-r494-54fq)
