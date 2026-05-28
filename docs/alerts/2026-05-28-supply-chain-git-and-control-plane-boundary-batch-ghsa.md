# TUF delegation, Dulwich Git, and Arcane control-plane boundary batch (GHSA, 2026-05-28)

**Signal:** GitHub Advisory Database published a late May 28 batch with durable offensive-operator value around updater trust metadata, Git-compatible checkout/merge behavior, and authenticated application control planes. The reusable lesson is to test whether a tool that consumes attacker-controlled metadata normalizes the same path, target, or file boundary on every platform before it makes a trust decision or executes helper behavior.

Promoted items:

- `GHSA-qp9x-wp8f-qgjj`: `tuf <= 6.0.0` uses `fnmatch.fnmatch()` for delegated target path matching. On Windows, Python normalizes case and path separators before matching, so case-colliding delegation patterns can authorize a target from the wrong delegated role.
- `GHSA-897w-fcg9-f6xj` / `CVE-2026-42305`: `dulwich >= 0.10.0, < 1.2.5` accepts NTFS-hostile tree entries on Windows, including backslash path separators, alternate-data-stream syntax, and incomplete `.git` 8.3 short-name aliases. A malicious repository can materialize files inside `.git` or outside the worktree during clone/checkout.
- `GHSA-9277-mp7x-85jf` / `CVE-2026-42563`: `dulwich >= 0.24.0, < 1.2.5` substitutes attacker-controlled merge paths into configured merge-driver commands through `%P` and executes with `shell=True`, creating command execution when a victim merges an untrusted branch with a vulnerable merge-driver setup.
- `GHSA-c3px-h233-h6fq` / `CVE-2026-47179`: `github.com/getarcaneapp/arcane/backend <= 1.19.3` lets an authenticated user create a project with Docker Compose `include:` directives that reference host files, then read those files through the project file API before path validation runs. Reading Arcane's SQLite database can expose password hashes/API keys and support escalation to admin and host RCE through Arcane's Docker control plane.

Use this only in authorized tests. Keep proofs to disposable repositories, lab Windows VMs, non-sensitive marker files, and test-only Arcane projects. Do not plant real hooks in a colleague's repository, read `/app/data/arcane.db` or host secrets from production, execute merge-driver payloads beyond a harmless marker command, or publish malicious repository artifacts outside a controlled harness.

## Operator checklist

### 1. TUF delegation matching drift on Windows

Where to look:

- Python TUF clients using `tuf <= 6.0.0` or downstream updaters that embed python-tuf `ngclient` behavior.
- TUF repositories with path-based delegated roles where role patterns differ only by case, such as `Foo/*` and `foo/*`.
- Windows update clients or mixed fleets where maintainers test on Linux/macOS but users fetch on Windows.

Safe validation workflow:

1. Confirm the client package version and whether the target platform is Windows.
2. In a lab TUF repository, create two delegated roles with case-colliding path patterns and deterministic delegation order.
3. Give the earlier, tester-controlled delegated role a harmless target whose path differs from the intended role only by case.
4. From a Windows test client, request the lower-case target path and verify whether the client accepts the earlier role's case-variant target.
5. Compare the same lookup on Linux/macOS to prove platform-dependent authorization rather than a generic delegation configuration mistake.
6. Stop at target-selection proof; do not distribute executable updater payloads or abuse real update channels.

Evidence to capture:

- `tuf` version, OS, and client code path.
- Delegation order and the two case-colliding path patterns.
- Target path requested versus target file and role actually accepted.
- Cross-platform comparison showing Windows-only case normalization.

Reporting heuristic: frame this as **platform-dependent TUF authorization drift**. Strong reports show that a delegated role not intended for a target namespace can satisfy that namespace on Windows because the matching API normalizes case before evaluating the delegation pattern.

### 2. Dulwich NTFS-hostile tree entries to checkout file-write/RCE

Where to look:

- Tools using Dulwich to clone, fetch, archive, or checkout untrusted repositories on Windows: developer portals, code review sandboxes, CI runners, package scanners, agent workspaces, and IDE integrations.
- Workflows that treat Dulwich as a Git-compatible parser but do not separately sandbox checkout materialization.
- Cross-platform pipelines where a POSIX service republishes repositories later consumed by Windows users.

Safe validation workflow:

1. Confirm `dulwich` version and the exact API or CLI path used for clone/checkout.
2. In a disposable malicious test repository, create only harmless marker entries that demonstrate path materialization drift, such as a `.git\\hooks\\pre-commit.marker`-style path or a `..\\outside-marker.txt` path.
3. Clone or checkout with the vulnerable Dulwich version inside a disposable Windows VM.
4. Verify whether Dulwich creates the marker inside `.git`, outside the worktree, or through an NTFS alternate-data-stream / 8.3 alias boundary.
5. Avoid executable extensions, real Git hook names, credential files, startup folders, or any persistence location in proof material.
6. Repeat with `dulwich >= 1.2.5` when possible to show rejection of `\\`, `:`, and `git~<digits>` forms.

Evidence to capture:

- Dulwich version and invoking application.
- Sanitized tree entry names used for proof.
- Before/after directory listing showing marker placement.
- Explanation of why the same tree entry is benign on POSIX but dangerous on Windows.

Reporting heuristic: high-value findings prove **Git parser / Windows filesystem boundary drift**. The strongest bug-bounty reports connect untrusted repository intake to a Windows checkout path where attacker-controlled tree entries can cross into `.git` or outside the worktree.

### 3. Dulwich merge-driver path command injection

Where to look:

- Automation that merges untrusted branches using Dulwich with custom merge drivers.
- Repositories that configure merge drivers in `.git/config`, service-managed config, template config, or developer environment setup.
- Merge drivers whose command uses the `%P` placeholder, because `%P` expands to the attacker-controlled path from the merge tree.

Safe validation workflow:

1. Confirm `dulwich >= 0.24.0, < 1.2.5` and identify a configured merge driver using `%P`.
2. In a disposable repository, create a branch with a filename that contains only a harmless command-separator marker intended to write a proof file in a lab directory.
3. Trigger the merge through the same Dulwich API or application workflow used by the target.
4. Verify whether the marker command runs because the merge-driver command is assembled as a shell string.
5. Keep payloads to `echo`/marker writes under a tester-owned temp path; do not run network callbacks, credential discovery, shell spawns, or destructive commands.

Evidence to capture:

- Dulwich version, merge-driver config, and `%P` usage.
- Sanitized malicious path name and the resulting command string if observable.
- Marker-file proof and merge transcript.
- Why attacker influence over repository path names is sufficient even when the merge driver itself is trusted.

Reporting heuristic: present this as **repository path to shell command injection**. The report is strongest when it demonstrates a real merge workflow that accepts untrusted branches and already has a `%P` merge driver configured.

### 4. Arcane Docker Compose include file read to control-plane escalation

Where to look:

- Arcane `<= 1.19.3` instances where authenticated users can create projects from Docker Compose content.
- Developer platforms, homelab dashboards, internal container portals, or bug-bounty scopes that expose Arcane to semi-trusted users.
- Arcane deployments where the backend can read sensitive host or application files and where admin access to Arcane controls Docker resources.

Safe validation workflow:

1. Confirm the Arcane backend version and that the test account can create projects.
2. Create a disposable project with Compose content that includes only a non-sensitive marker file path approved for testing, preferably a file created inside the lab container/host specifically for this proof.
3. Call the project file API for the include path and verify whether the response returns marker content before path validation.
4. If the program permits impact demonstration, explain the database-read escalation chain from the advisory without reading real `/app/data/arcane.db` or password/API-key material.
5. Do not access Docker control features, create containers, mount host paths, or pivot to RCE unless the engagement provides an explicit lab harness for that chain.

Evidence to capture:

- Arcane version and user role.
- Project creation request with Compose `include:` path redacted to the marker location.
- Project file API request/response showing marker content disclosure.
- Code-path explanation: create-project accepts include paths, include parsing reads arbitrary files, and project file content returns include content before `IsSafeSubdirectory` validation.

Reporting heuristic: frame this as **authenticated compose include read before path validation**. The best reports avoid dumping secrets; they prove the primitive with a marker file and then clearly map why Arcane's database and Docker control-plane privileges make the primitive high impact.

## Reviewed but not promoted standalone

- `GHSA-6v92-ph9p-hrpc`, `GHSA-6h8r-h22r-jj64`, `GHSA-4qf2-p32m-7hmf`, `GHSA-3x4g-259h-5p7c`, and `GHSA-fxvj-wqv2-xgcq`: OMEC AMF NGAP handling issues mention public exploit availability, but the current advisory text is low-detail and mostly availability/memory-corruption oriented without a stable Skillz validation workflow beyond telecom-lab fuzzing.
- `GHSA-cvwm-vwhp-22jx` / `CVE-2026-8771`: litemall WeChat API SQL injection is potentially useful for target-specific testing, but the public advisory is too terse to add a distinct operator page beyond normal parameterized SQLi validation.
- CISA KEV stayed catalog `2026.05.28` with top entries already reflected or previously triaged for this wiki. PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, and Disclosed had no additional promotable deltas in this pass.

## References

- [python-tuf delegation path matching advisory (`GHSA-qp9x-wp8f-qgjj`)](https://github.com/advisories/GHSA-qp9x-wp8f-qgjj)
- [Dulwich NTFS-hostile tree entry advisory (`GHSA-897w-fcg9-f6xj`)](https://github.com/advisories/GHSA-897w-fcg9-f6xj)
- [Dulwich merge-driver command injection advisory (`GHSA-9277-mp7x-85jf`)](https://github.com/advisories/GHSA-9277-mp7x-85jf)
- [Arcane Docker Compose include file-read advisory (`GHSA-c3px-h233-h6fq`)](https://github.com/advisories/GHSA-c3px-h233-h6fq)
- [Dulwich project](https://github.com/dulwich/dulwich)
- [python-tuf project](https://github.com/theupdateframework/python-tuf)
- [Arcane project](https://github.com/getarcaneapp/arcane)
