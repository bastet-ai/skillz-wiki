# asyncssh client-side write-path boundary checks: SCP traversal and AuthorizedKeysFile username escapes

**Signal:** GitHub Security Advisories, 2026-08-27 hourly scan (two asyncssh records, published 2026-08-26). This is a durable operator pattern: **a file-transfer or SSH client trusts the remote side's naming material to choose where to write on the local machine**. The same class recurs across SCP, SFTP, rsync-over-ssh, and download-manager integrations, so it is worth a reusable validation workflow.

## What changed

- [GHSA-2wxc-x7rj-hg8f / CVE-2026-54591](https://github.com/advisories/GHSA-2wxc-x7rj-hg8f) (high, `asyncssh` pip, all versions through `2.23.0`, fixed `2.23.1`): the **SCP receive path does not sanitize server-provided filenames**. A malicious SSH/SCP server sends `C`/`D` protocol lines whose filename fields carry `../` sequences (and `D` directory actions to climb), and the client resolves them with `posixpath.join(dstpath, name)` and opens the result for write. The advisory documents the class explicitly: same vulnerability family as OpenSSH CVE-2019-6111. The reachable local targets named are `~/.bashrc`, `~/.profile`, `~/.ssh/rc`, `~/.ssh/authorized_keys` — i.e. the classic persistent-access file set for the user that runs the client.
- [GHSA-qr67-gv47-xwwh / CVE-2026-54590](https://github.com/advisories/GHSA-qr67-gv47-xwwh) (medium, `asyncssh` 2.23.0 through current `develop`): **incomplete fix for CVE-2026-45309**. The 2.23.0 guard in `SSHServerConfig._set_tokens` rejects usernames containing `/`, `\`, and `..` before `%u` substitution in `AuthorizedKeysFile`, but a **leading `~`** (and weakly `${ENV}`) is not rejected and is re-expanded after the guard, so the resulting path still escapes the intended directory. This is the fix-drift variant: the sanitizer's character list is narrower than the expansion rules it feeds.

The operator lesson generalizes beyond asyncssh:

1. **Server-controlled filename -> local write path.** Any client that lets the remote choose the destination filename (SCP, SFTP with client-side path joining, download managers that use remote-supplied names) must normalize and confine the final path to the requested directory.
2. **Sanitizer vs expander mismatch.** Guards that run *before* shell/tilde/env expansion must account for what the expansion layer reintroduces (`~`, `${...}`, `$(...)` depending on the expander). Test the guard against post-expansion results, not just pre-expansion strings.

## Operator triage

1. **Inventory asyncssh users.** Find Python code that calls `asyncssh.scp()` (or wraps SCP/SFTP transfers) in automation, CI runners, backup tooling, or data-movement scripts. Note the installed `asyncssh` version: anything `< 2.23.1` is in range for the SCP traversal; `2.23.0` (and `develop` after that) is in range for the `AuthorizedKeysFile` username-escape follow-up.
2. **Ask who controls the server side.** The exposure is only when the *server* of a transfer is untrusted or attacker-reachable (a malicious host you pull from, a compromised mirror, a man-in-the-middle that can replace the SCP exec payload). If both ends are trusted and pinned, the risk is supply-chain-adjacent rather than a live primitive.
3. **Confirm the local write user.** Impact ceiling = the user that runs the client process. A root-scoped runner turns a marker write into a root persistent-access primitive.
4. **Check the `AuthorizedKeysFile` config path** in lab SSH *servers* built on asyncssh: any `%u`-templated path plus a username-accepting login path is the surface the second advisory targets.

## Replayable validation boundaries

All validation is lab-only: a disposable malicious SSH/SCP server you control, a disposable client host, and marker files. Do not target real hosts, do not write real credentials or keys anywhere, and do not complete a login from a planted key on any live system.

### SCP server-controlled filename check

1. Build the lab: a disposable asyncssh-based SCP/SSH server that answers the `scp -f` exec channel with a fixed script of protocol lines, and a client node that runs `asyncssh.scp((conn, 'file'), '<marker-dir>')` against it.
2. The server script uses only **marker** destinations: one in-root `C` line (baseline), one `C` line whose filename is a sibling marker above `<marker-dir>` (single `../`), and one `D` + `C` pair that climbs two levels then writes a marker. No payload content beyond a fixed text canary.
3. Record the client's resolved open path for each line (patch or log `posixpath.join` / the final `open`), and which marker appears where after the transfer.
4. The vulnerable result is a marker file landing **outside the requested download directory**. The secure result (`2.23.1+`) is every write confined to `<marker-dir>`, or the traversal lines rejected before any open.
5. Keep the proof at the filesystem layer: the finding is **server filename field -> unsanitized join -> open outside the requested directory**. Do not claim RCE without separately demonstrating an executing target in the lab.

### AuthorizedKeysFile username-escape check

1. Lab SSH server built on the affected asyncssh versions with `AuthorizedKeysFile` templated with `%u`, pointing at a directory inside a disposable user home.
2. Connect with three synthetic usernames: a benign one (control), one containing a leading `~` segment, and one containing a `${ENV}`-shaped segment. All three carry no real key material; authentication is denied or completed against a throwaway account.
3. Patch or log the final file-open path after token substitution and expansion. A positive is the resolved path **leaving the intended `authorized_keys` directory** for the `~`/`${ENV}` usernames while the `/` / `..` control cases stay confined.
4. Repeat on a patched build or the upstream fix to record the corrected behavior. Never point the resolved path at a real home directory, real SSH config, or a real `authorized_keys` on any host.

## Reporting heuristics

- Lead with the exact transition: **server-provided filename -> client path join -> local write outside requested directory**, or **SSH username -> `%u` substitution -> post-expansion path outside the templated directory**.
- Name the client version, the protocol class (SCP `C`/`D` lines vs SFTP), and the guard that failed. For the second record, show the guard's reject list next to the character class it missed (`~`, `${ENV}`).
- Separate the two findings: the first is a missing sanitization on a data path; the second is a partial-fix regression on a config path. They have different entry points and different proofs.
- Do not plant real keys, real cron entries, or real shell files. The lab proof is a marker landing where it should not, plus the version delta.

## Safety constraints

- Disposable client and server nodes only; no shared or production hosts.
- No real credentials, SSH keys, or tokens in any fixture.
- No execution of written content; the primitive is the unconfined write, escalation is a separate step that must be proven (and then bounded) in isolation.
- Do not run these checks against untrusted remote servers in a production data pipeline; the exposure is real, so treat any live hit as a compromise indicator for the pipeline, not a test artifact.

## October 13 follow-up: scp.py client-side receive traversal — the same bug in the second Python SCP client (CVE-2026-109152 / [GHSA-3f22-449q-g7c5](https://github.com/advisories/GHSA-3f22-449q-g7c5), medium, `jbardin scp.py ≤0.16.1`, fixed 0.16.2, patch 42fc3aa)

The 12:32Z wave landed the direct twin of this page's asyncssh finding: **`_recv_file`/`_recv_pushd` in scp.py's SCP receive handler trust server-supplied `C`/`D` filename fields**, so a malicious SCP server's traversal names write outside the requested download directory — OpenSSH CVE-2019-6111's family again, now confirmed in both Python SCP clients. The fix commit (42fc3aaa714) is public, which doubles as the reference sanitization shape for audits.

Operator update: this makes the class **grep-able across the ecosystem** rather than product-specific — `grep -rn "recv" */scp*`-style sweeps for SCP-protocol parsers that `join(dir, name)` without confinement are a standing recon task on any pipeline that automates downloads from third-party SSH servers. When you find one, the asyncssh lab harness above transfers verbatim: disposable malicious server, marker `C`/`D` lines, resolved-path logging, patched-version negative control. Treat a live pipeline hit as a compromise indicator (an attacker who controls the remote server owns your download host's file writes), not a test artifact.
