# Git LFS wave (4 GHSAs): malicious repo config and SSH URLs make clones run attacker commands

Source: hourly offensive-security scan, 2026-11-20 (Git LFS coordinated wave published 14:47Z-14:59Z, all fixed in v3.8.1, defect ages 0.5.0-1.3.0+).

**Wave in one line:** cloning an attacker-controlled repository with Git LFS installed can execute code on the developer workstation through the repository-provided `.lfsconfig` allowlist bypass, submodule config newline forgery, unquoted SSH transfer command construction, or Cookie leakage across LFS endpoint redirects.

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-x72p-hmqp-46hw](https://github.com/advisories/GHSA-x72p-hmqp-46hw) | CVE-2026-105803 | high | `.lfsconfig` permits a limited set of config options, but the allowlist is bypassed when a key contains certain **additional key components**, letting repo content mimic the custom object-transfer command option; Git LFS then invokes an attacker-supplied command when fetching objects. Exists since 1.3.0. Fix restricts custom transfer commands to **local** git config only. |
| [GHSA-xrgv-7vx6-5vx6](https://github.com/advisories/GHSA-xrgv-7vx6-5vx6) | CVE-2026-105802 | high | Git LFS reads git configuration **without rejecting embedded control characters**; injecting an LF into a submodule config value forges additional option lines so a follow-on option that sets a custom transfer command appears legitimate, executing an arbitrary command on fetch or add. Exists since 0.6.0. Fix moves config parsing to an unambiguous format. Workaround: disable `fetch.recurseSubmodules` and `submodule.recurse`, never run `git submodule init`, `git submodule deinit` any initialized submodule. |
| [GHSA-w3f2-pr6x-wwjc](https://github.com/advisories/GHSA-w3f2-pr6x-wwjc) | CVE-2026-69260 | high | On SSH transfers, Git LFS embeds the **path component of the remote's SSH URL into a command string without formatting it as a single argument**; shell metacharacters in the URL path execute on the remote host if the server hands commands to a shell unsanitized. Same release fixes wrong HTTPS-URL encoding in the `git-lfs-authenticate` fallback path. Exists since 0.5.0. Workaround: `git config lfs.sshTransfer never` (note: authentication requests to SSH URLs still occur). |
| [GHSA-x7xj-4j4f-88xr](https://github.com/advisories/GHSA-x7xj-4j4f-88xr) | CVE-2026-69261 | high | After an HTTP redirect, Git LFS forwards **`Cookie` headers to a host other than the one they were intended for** (`Authorization` was already correctly withheld). Fix stops forwarding Authorization and Cookie whenever redirect changes scheme, host, or port. Exists since 0.5.0. |

## Why this is worth an operator page

Git LFS is the most-installed repository-adjacent binary on developer machines, and every leg here is triggered by content the **repository** controls: the `.lfsconfig` file, submodule git config, the remote URL string, and the LFS endpoint's HTTP redirects. That makes `git clone --recursive` of a crafted repo a code-execution primitive on the workstation that clones it, which is a direct supply-chain foothold path for authorized red-team engagements and a strong bug-bounty class against hosted git services and LFS backends.

The four legs also teach four transferable audit patterns: repo-provided config files parsed against key allowlists, config values parsed without control-character rejection, command strings built from URL components, and per-header-class parity on redirect following.

## Durable operator rules

1. **Repository-provided config files are attacker input, and allowlist *parsers* are the bypass surface.** The `.lfsconfig` defect is not the allowlist, it is the key grammar: options with certain additional key components (subsection/extra-component spellings) escaped the allowlist comparison and re-admitted the custom transfer-command option. This is the same family as the June 22 `.tool-versions` Tera execution and `.pdm-plugins` pre-parse execution entries: any tool that reads a repo-local config and allowlists keys must be tested with key-shape variants (extra components, quoting, case, whitespace, control bytes), not just blocked key names.
2. **Value-embedded control characters convert "value" into "next key".** Git config's line-based format means an LF inside a value forges a new key line. Any line-based parser that does not reject CR/LF in values (the fix wording: "always use an unambiguous format") is a config-forgery candidate. Fingerprint for hunting: parsers that round-trip `key=value` text instead of using a structured reader.
3. **A remote URL is a command argument waiting to be quoted.** Client tools that build remote commands from URL components (here, the SSH path component into the `git-lfs-authenticate` command channel) need full shell quoting on the client *and* server-side sanitization; the vendor shipped both obligations. As an attacker hitting a hosted git service, send SSH URLs with metacharacters and observe server behavior; as a service admin, sanitize every SSH-received command before exec, and test `lfs.sshTransfer=never` parity (auth requests still cross the SSH channel even with transfers disabled).
4. **Redirect credential leakage is per-header-class, not per-credential.** Authorization was withheld on cross-origin redirects but Cookie was not. When testing any HTTP client library or agent that follows redirects to attacker-influenced endpoints (LFS batch endpoints are themselves redirect-followable), enumerate the header inventory individually: Authorization, Cookie, custom bearer headers, API-key headers, proxy headers. One correctly-handled header does not certify the rest (same lesson as the hapi Wreck credential-header-across-redirect family already on the wiki).
5. **Defect ages of 6-11 years across "since 0.5.0"/"since 1.3.0" mean the entire installed base was exposed until one release.** On engagements, fingerprint `git lfs env` / `git-lfs version` on any workstation, CI runner, or build agent you reach; <3.8.1 plus the ability to get a user to clone (README lure, vendored dependency repo, partner handoff) is the whole attack precondition.

## Replayable validation boundaries (lab only)

- **Repo-provided config harness:** in a disposable bare repo on a lab host, plant `.lfsconfig` with a transfer-command key using key-shape variants (extra components per the advisory description) whose value is an inert marker script that touches a canary file. Clone with Git LFS <3.8.1 into a throwaway directory and record whether the marker executes; replay the same clone on 3.8.1 as the patched control. Never use a reverse shell or anything that egresses.
- **Submodule newline-forgery harness:** seed a submodule whose git config value embeds an LF followed by a custom-transfer-command key set to the inert marker. Clone `--recursive` with submodules initialized; positive evidence is marker execution attributable to the forged line. Capture raw config bytes (`git config --list --show-origin`, hex dump of the poisoned file) as the evidence artifact.
- **SSH URL quoting harness (owned server only):** run a lab git host whose `git-lfs-authenticate` path logs received commands verbatim; attempt SSH remotes whose path component carries quoting-sensitive canaries (quote pairs, backticks, semicolons). Evidence is the recorded command string on your own server, proving client-side quoting state. For service-side review, verify the server sanitizes before shell handoff regardless of client version.
- **Cookie-forwarding harness:** point a lab LFS batch endpoint at a 302 to an owned collector on a different host with a distinct Cookie jar; capture which headers arrive. Compare header-by-header against the patched build's behavior and record a per-header forwarding decision table.
- **Patched-control discipline:** every positive above must be re-run on v3.8.1 with the same fixtures; a differential against the patched version is what makes the finding reportable.

## Reporting notes

- State the crossed boundary precisely: **repository file to client command execution** (both config legs), **URL component to remote command string** (SSH leg), or **redirect to cross-origin credential header** (Cookie leg).
- Evidence that reads well: hex-dumped poisoned config, marker-file mtimes, recorded server-side command strings, per-header forwarding tables, patched-vs-vulnerable differential pairs.
- Do not ship weaponized transfer-command payloads in a report; inert marker scripts prove execution and stay safe to attach.

## Tracked without publication this run

- aMQTT regex-complexity/resource-consumption leg ([GHSA-2hjf-7455-w946](https://github.com/advisories/GHSA-2hjf-7455-w946)) plus unmanaged QoS 2 session memory-leak DoS ([GHSA-wcqj-wx85-c75p](https://github.com/advisories/GHSA-wcqj-wx85-c75p)): protocol-parser availability pair, no new operator axis.
- go-guerrilla bare-XCLIENT off-by-one panic ([GHSA-hghq-53p7-c582](https://github.com/advisories/GHSA-hghq-53p7-c582)): fixed-length slice on command name, parser-crash class already covered.
- js-toml deep-recursion `load()` RangeError ([GHSA-3g82-77xr-68x5](https://github.com/advisories/GHSA-3g82-77xr-68x5)): parser recursion DoS, tracked.
- TeamPass folder re-parenting authorization bypass ([GHSA-66q9-mxf2-xqw6](https://github.com/advisories/GHSA-66q9-mxf2-xqw6)): parent-only IDOR family already promoted on the November 20 FlowIntel page; thin single.
- storyblok-backup stored path traversal via component names in backup filenames ([GHSA-vcx7-pfrh-mcfg](https://github.com/advisories/GHSA-vcx7-pfrh-mcfg)): filename-keyed write class, tracked.
- OpenRemote cross-realm MQTT session disconnect without authorization ([GHSA-3h6w-xcw3-9xjj](https://github.com/advisories/GHSA-3h6w-xcw3-9xjj)): cross-tenant availability leg, tracked unless a control-plane twist lands.

---

*Source: hourly offensive-security scan, 2026-11-20. Wave tracked in the [source index](../notes/source-index.md).*
