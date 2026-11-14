---
title: Privileged PID-file symlink boundary validation
---

# Privileged PID-file symlink boundary validation

[GHSA-7wr7-q3ph-825q / CVE-2025-52936](https://github.com/advisories/GHSA-7wr7-q3ph-825q) turns a familiar local file primitive into a reusable service-review workflow: a daemon opens a configured PID file while privileged, follows a pre-positioned symbolic link, and truncates the link target before dropping privileges. The affected `sslh` path is fixed in 2.2.2.

Primary implementation evidence:

- [`sslh` pull request 494](https://github.com/yrutschle/sslh/pull/494) replaces `fopen(pidfile, "w")` with an `open()` call using `O_NOFOLLOW` where available;
- the affected 2.2.1 startup sequence calls `write_pid_file(cfg.pidfile)` before `drop_privileges(cfg.user, cfg.chroot)`; and
- the GitHub advisory was unreviewed at scan time. Confirm the exact packaged source and startup configuration rather than treating database severity as proof of reachability.

!!! warning "Disposable local lab only"
    Use a container or VM, a temporary PID directory, and a random text canary. Never point a test symlink at system configuration, credentials, shell startup files, logs, databases, service units, or another user's data. Do not restart a production service to test this primitive.

## Why this is durable

PID files, lock files, status snapshots, Unix sockets, and startup logs are often created before a daemon relinquishes privilege. The useful assessment question is not merely whether the final path is a symlink. It is whether a lower-trust principal can control any path component at the moment a privileged open applies `O_CREAT`, `O_TRUNC`, or write access.

The complete exploit precondition is:

**attacker-writable path or replaceable PID entry -> privileged pre-drop open -> link following -> controlled target truncation or write**

If the PID directory and existing entry are root-controlled and cannot be replaced, the vulnerable sink may not be reachable by the assessed principal. Record that negative result rather than claiming impact from source inspection alone.

## Prerequisites and inputs

- exact daemon binary or package version and source provenance;
- service manager configuration, command line, and effective PID-file path;
- startup ordering for PID creation and privilege drop;
- owner, mode, ACL, mount, namespace, and sticky-bit state for every path component;
- a disposable working directory and synthetic target file; and
- `strace` or an equivalent file-open recorder.

Keep three identities separate in evidence: the principal that can prepare the path, the identity that opens the PID file, and the daemon's post-drop identity.

## Static path-to-sink review

1. Resolve configuration aliases, environment expansion, relative paths, service-manager substitutions, and container bind mounts to the effective PID-file path.
2. Trace startup from argument/config parsing to PID creation and then to `setuid`, `setgid`, `chroot`, or the daemon's equivalent privilege transition.
3. Identify the open flags. `fopen(path, "w")` commonly implies creation and truncation and follows a final symlink. A corrected final-component check should reject links atomically, such as with `O_NOFOLLOW`; a separate `lstat()` followed by `open()` is raceable.
4. Check parent components as well as the final entry. Final-component `O_NOFOLLOW` does not by itself stop traversal through attacker-replaceable parent symlinks.
5. Determine whether the lower-trust principal can create, rename, or replace the final entry. Include sticky directories, ACLs, service-specific runtime-directory creation, and stale-file cleanup behavior.

Record a compact boundary table:

| Stage | Evidence |
| --- | --- |
| Path selection | raw configured value and resolved absolute path |
| Attacker control | writable/replaceable component and principal |
| Privileged sink | syscall, flags, effective UID, and startup position |
| Canonical target | final resolved synthetic path |
| Corrected control | link rejection and unchanged canary on fixed build |

## Recorder-first lab workflow

Create the fixture as an unprivileged user; privilege is unnecessary to demonstrate link-following semantics. Use a randomized directory and preserve the canary's digest before and after each run.

```bash
lab="$(mktemp -d)"
mkdir -m 700 "$lab/run"
printf 'PIDFILE-CANARY-%s\n' "$(date +%s)" > "$lab/target.txt"
ln -s "$lab/target.txt" "$lab/run/sslh.pid"
sha256sum "$lab/target.txt"
readlink -f "$lab/run/sslh.pid"
```

Then exercise the exact affected binary or a source-built 2.2.1 artifact under a syscall recorder. Configure every listener to loopback, disable unrelated integrations, and stop after PID-file creation.

```bash
strace -ff -o "$lab/trace" -e trace=openat,write,close \
  /path/to/isolated/sslh-2.2.1 -F /path/to/lab-only.cfg
```

The configuration should select only `"$lab/run/sslh.pid"` as its PID path. Do not paste a generic daemon command into a privileged host: package flags and service-manager behavior differ. Inspect the trace for the PID path, open flags, effective execution context, and whether the canonical synthetic target changed.

Repeat with these controls:

1. a regular PID file in the same directory;
2. a dangling symlink;
3. a symlink to the random canary;
4. an attacker-replaceable parent-directory symlink;
5. the exact 2.2.2 or downstream-corrected package; and
6. a service-manager-created root-owned runtime directory that the test principal cannot modify.

For the corrected final-link case, expected evidence is an `openat()` failure such as `ELOOP` and an unchanged canary. Test parent-component replacement separately; do not infer that `O_NOFOLLOW` secures the entire path walk.

## Bounded positive and reporting

A strong positive requires all of the following:

- the assessed lower-trust principal can prepare or replace the effective PID entry;
- startup reaches the PID-file sink before privilege drop;
- the recorded open follows the link and applies truncation or a PID write to the synthetic target; and
- the corrected build or a root-owned runtime-directory control blocks the same transition.

Report the narrow primitive first: **replaceable PID entry -> privileged pre-drop `fopen("w")` -> symlink target truncation/write**. Include package hash, service configuration, component permissions, syscall excerpt, pre/post canary hashes, effective identities, and corrected-build result.

Do not automatically claim code execution or privilege escalation. Those outcomes require a separate, authorized proof that a security-sensitive file is both selectable and meaningfully transformed by the daemon's short PID content. A canary truncation is sufficient to validate the file-authority boundary.

## Adjacent advisory triage

### August 11 MRTG ownership-change follow-up

[GHSA-pqrp-p4c6-2q4g / CVE-2026-72694](https://github.com/advisories/GHSA-pqrp-p4c6-2q4g) adds a distinct PID-path side effect: an MRTG daemon started as root reportedly drops privilege but can follow a pre-positioned PID-file symlink when changing file ownership. Reuse the path-control and startup-order inventory above, but patch `chown`/`fchownat` rather than looking only for truncating opens.

In a disposable VM, create a random sibling canary owned by a synthetic user and point only the temporary MRTG PID entry at it. Record every component's ownership/ACL, effective identity, `lstat`/open sequence, canonical target, requested owner/group, and privilege-drop position. Interpose the ownership syscall and deny it. Compare a regular PID file, final symlink, replaceable parent, root-owned runtime directory, affected package, and corrected package.

The bounded positive is **low-privilege principal can prepare the PID path -> root MRTG startup follows it -> denied ownership syscall selects the synthetic sibling canary for transfer to the daemon user**. Do not change ownership of the canary, target privileged files, or claim escalation without a separately proven consumer. This differs from the `sslh` case: the reportable primitive is ownership transfer, not truncation.

The same hourly wave also surfaced [GHSA-fffv-7w63-p3xw / CVE-2026-18556](https://github.com/advisories/GHSA-fffv-7w63-p3xw), a sparse N-able N-central alternate-path authentication-bypass record, and [GHSA-96xh-5wq4-m4cc / CVE-2024-10918](https://github.com/advisories/GHSA-96xh-5wq4-m4cc), a libmodbus unexpected-length memory-safety record. Neither supplied enough route, parser, or build detail in this scan to publish a replayable operator workflow; they are retained as source leads rather than generalized into unsupported exploit instructions.

### November 14 ABRT follow-up: the PID itself is client-supplied input, root copies `/proc/<pid>/environ` for you, and the completeness fix was one unprivileged file away from bypassed (wrxw/CVE-2026-110330 + xxg9/CVE-2026-110331)

ABRT extends this page's "privileged process trusts a low-privilege-chosen path" rule to a new trust object: **not a file path but a process identifier**. In wrxw, `abrt-server` accepts a client-supplied PID over `abrt.socket`, runs as root, and copies that process's `/proc/<pid>` data, **including `environ`**, into a dump directory owned by the connecting unprivileged user. A local attacker names any PID (another user's session, root services) and reads its environment: secrets, tokens, and connection strings that never touched disk.

- **Identifier-as-input audit:** every privileged helper that resolves a caller-nominated identifier (PID, uid, inode, bus name, socket peer) into kernel/procfs state has the same shape as the PID-file symlink case, the identity/authorization check, if any, must bind the identifier to the requester. Probe pattern on any socket-activated root daemon: connect as an unprivileged lab user, offer a canary process whose environment contains a disposable marker, and check whether the marker lands in a directory you own.
- **`/proc/<pid>/environ` is the payload, and the dump directory is the exfil channel.** Unlike a symlink truncation, the read primitive completes in one request with no file pre-positioning; environment-content leakage from setuid/systemd/service contexts is a standing local recon target once any root consumer is persuaded to copy it.
- Incomplete-fix twin xxg9: the mitigation for CVE-2026-54228/54229 added a "completeness check" that only verifies a dump directory contains a `count` element, an element **the unprivileged user can create**, so directory poisoning/ownership seizure returns, and other Problems2 mutating methods were never gated at all. Rule for fix-differential testing: when a guard checks for the *presence* of attacker-writable state, the guard is the attacker's; enumerate sibling mutating methods on the same object store, partial gating is the norm on fix days.
- Validation boundary: disposable VM with abrtd running, lab users, synthetic canary processes with marker environments only; never name PIDs of third-party or production processes.