# Agent repository, MCP file-read, and registry trust-boundary checks

Source: hourly offensive-security scan, 2026-07-01. Primary entries: GitHub Advisory Database [GHSA-hwpp-h97w-2h3j](https://github.com/advisories/GHSA-hwpp-h97w-2h3j), [GHSA-9mm9-rqhj-j5mx](https://github.com/advisories/GHSA-9mm9-rqhj-j5mx), [GHSA-gvpp-v77h-5w8g](https://github.com/advisories/GHSA-gvpp-v77h-5w8g), [GHSA-cv2p-68f4-f4pw](https://github.com/advisories/GHSA-cv2p-68f4-f4pw), and [GHSA-6c87-g9pw-78fx](https://github.com/advisories/GHSA-6c87-g9pw-78fx).

These advisories are durable for operators because they expose recurring boundaries in AI and developer tooling: repository-controlled arguments crossing into Git, MCP tool paths bypassing file-read guards, IDE project directories being trusted as developer checkouts, command allowlists that miss shell execution variants, and registry host matching leaking credentials to sibling domains. Keep proofs to disposable repositories, inert commands, fake secrets, local canary files, owned registries, and isolated agent profiles.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-hwpp-h97w-2h3j](https://github.com/advisories/GHSA-hwpp-h97w-2h3j) / CVE-2026-49988 | `repomix <= 1.14.0` MCP `attach_packed_output` / `read_repomix_output` | an alternate packed-output path can read local `.json`, `.txt`, `.md`, or `.xml` files without the `file_system_read_file` secret scan | Test every MCP file-like tool, not only the obvious read primitive; prove secret-guard bypasses with fake marker files only. |
| [GHSA-9mm9-rqhj-j5mx](https://github.com/advisories/GHSA-9mm9-rqhj-j5mx) / CVE-2026-49987 | `repomix < 1.14.1` `--remote-branch` | branch input is appended to `git fetch` / `git checkout` without a positional `--` delimiter, allowing Git option injection | Repository and branch selectors in AI/code-packaging tools are command surfaces; validate with dry-run argument logging or inert marker scripts in a lab. |
| [GHSA-gvpp-v77h-5w8g](https://github.com/advisories/GHSA-gvpp-v77h-5w8g) / CVE-2026-49986 | `neuro-cortex-memory <= 3.17.0` Cortex MCP `open_visualization` | `CLAUDE_PROJECT_DIR` is treated as a trusted Cortex source root after checking only marker paths | A malicious project opened in an IDE can become bootstrap code; test project-directory trust with inert marker files and fake visualization bootstraps. |
| [GHSA-cv2p-68f4-f4pw](https://github.com/advisories/GHSA-cv2p-68f4-f4pw) / CVE-2026-36045 | `picoclaw <= 0.1.2` `ExecTool` | denylist-based command guards miss executable shell variants | Agent shell tools need positive policy and tokenized execution evidence; do not trust short regex denylist demos. |
| [GHSA-6c87-g9pw-78fx](https://github.com/advisories/GHSA-6c87-g9pw-78fx) | Contrast Imagepuller `Config.registryFor` | unanchored suffix host matching can apply registry credentials, custom CAs, mirrors, or TLS-skip settings to sibling domains such as `evilghcr.io` for `ghcr.io` | Container pull assessments should include exact-label registry matching tests and owned sibling-domain canaries. |

## Operator triage

1. **Inventory agent/developer trust inputs.** List MCP tools, repository URLs, branch/tag/reference fields, active IDE project directories, shell/exec helpers, image registries, and per-registry credentials before testing payloads.
2. **Prioritize alternate paths.** If a product advertises one guarded file-read or command-exec path, search for secondary helpers that read, attach, import, pack, preview, visualize, or execute the same underlying resource with different checks.
3. **Treat branch names as untrusted arguments.** Any tool that runs `git fetch`, `git checkout`, `git clone`, or package manager commands using branch/reference values should show a `--` delimiter or strict reference grammar.
4. **Project-root detection is not trust.** Marker files such as `mcp_server/`, `ui/unified-viz.html`, `.tool-versions`, or project-local config should not cause code execution unless the user explicitly opted into that repository as trusted.
5. **Registry suffix matches leak secrets.** For image pullers and package registries, compare configured host `example.com` against `evil-example.com`, `evilexample.com`, `example.com.evil.invalid`, trailing-dot forms, and exact subdomain policy.

## Replayable validation boundaries

### Repomix MCP local file-read guard bypass

- Preconditions: disposable workstation or container, affected `repomix --mcp` server, no real secrets mounted, and an MCP client or harness that can call tools directly.
- Create a fake local file with an allowed extension, for example `/tmp/skillz-repomix-canary.txt`, containing only `SKILLZ_REPOMIX_FAKE_SECRET_<case-id>`.
- First call the documented guarded read primitive if available and record the expected secret-scan decision for the same file.
- Call `attach_packed_output` with the canary file path, then call `read_repomix_output` with the returned `outputId`.
- Positive evidence: the packed-output path returns the marker even though the normal read path would be blocked or scanned. Do not target `.env`, SSH keys, shell history, API tokens, notebooks, or customer source files.
- Negative controls: patched version, schema/header validation for packed outputs, and a shared secret-scan/file-policy layer used by every local-file tool.

### Repomix branch argument-injection harness

- Preconditions: isolated lab VM, throwaway repository, no SSH agent or production Git credentials, and an inert payload that only writes a temp marker.
- Use a harmless branch/reference value that starts with a Git option in a controlled harness and capture the actual argv passed to `git fetch` / `git checkout`. Prefer wrapper logging over executing real helper binaries.
- If execution must be demonstrated, use a temp script that writes `/tmp/skillz-repomix-branch-canary` and exits; never run network callbacks or destructive shell commands.
- Positive evidence: the untrusted branch value is interpreted as a Git option such as `--upload-pack` rather than a branch name.
- Negative controls: branch grammar validation, explicit `--` before refs, rejection of leading `-`, and patched `repomix >= 1.14.1`.

### Cortex `CLAUDE_PROJECT_DIR` bootstrap trust check

- Preconditions: disposable Claude Code / MCP lab profile, affected `neuro-cortex-memory`, and a temporary project directory that is not a real Cortex checkout.
- Create only the marker structure needed to mimic a Cortex root plus an inert `mcp_server/server/visualize_bootstrap.py` that writes a temp marker and prints a canary string.
- Set or simulate `CLAUDE_PROJECT_DIR` to that project and invoke `open_visualization`.
- Positive evidence: the MCP server executes the project-local bootstrap solely because marker files exist under the active IDE project.
- Negative controls: ignore `CLAUDE_PROJECT_DIR` for developer source discovery, require explicit `CORTEX_DEV_ROOT` opt-in, verify package/repository identity, or run packaged visualization code only.

### Picoclaw `ExecTool` command-policy probe

- Preconditions: local lab instance, low-privilege test user, and commands limited to inert marker creation or `printf`.
- Build a decision table of allowed/denied shell strings: direct blocked tokens, quoting variants, shell builtins, environment assignment, path-qualified binaries, command substitution, separators, and newline/IFS variants.
- Positive evidence should show a command that policy intends to deny but the tool executes. Stop at marker creation; do not publish payloads that download code, spawn reverse shells, or read host files.
- Negative controls: allowlist exact executable plus fixed arguments, no shell when a direct exec API works, canonical tokenization before policy, and per-tool capability scopes.

### Contrast Imagepuller registry suffix canary

- Preconditions: lab imagepuller configuration, fake registry credentials, an owned callback/registry hostname, and no production image credentials.
- Configure a registry block for a target host such as `ghcr.io` using fake `Authorization` material and, if relevant, a fake custom CA or mirror setting.
- Attempt a pull from an owned sibling hostname that ends with the same byte sequence, such as `skillzghcr.io`, using a digest-pinned inert image reference.
- Positive evidence: the owned sibling receives the fake auth header or the imagepuller applies the configured CA/mirror/TLS policy intended for the real registry host.
- Negative controls: exact DNS-label equality, leading-dot semantics for subdomains, trailing-dot normalization, and no credential forwarding unless the requested host exactly matches the configured registry scope.

## Reporting notes

- Lead with the crossed boundary: MCP alternate file path to local file-read guard bypass, branch string to Git option, active IDE project to bootstrap execution, shell denylist to command execution, or registry suffix to credential leak.
- Include affected package/version, tool invocation route, normalized path/argv/host evidence, canary value label, and patched negative control.
- Keep evidence synthetic. Do not read real secrets, source files, prompts, notebooks, model weights, package tokens, image registry credentials, or operator SSH/Git configuration.

## July 2 Coder, Dulwich, and Kerberos Hub follow-up

Later July 2 GitHub Advisory Database entries add three adjacent developer-control and credential-boundary cases: [GHSA-m3cr-vc2j-pm27](https://github.com/advisories/GHSA-m3cr-vc2j-pm27) / CVE-2026-44454 for Coder dotfiles workspace auto-creation, [GHSA-gfhv-vqv2-4544](https://github.com/advisories/GHSA-gfhv-vqv2-4544) / CVE-2026-52726 for Dulwich submodule path traversal into `.git/hooks`, and [GHSA-h5gx-45rj-2h5j](https://github.com/advisories/GHSA-h5gx-45rj-2h5j) / CVE-2026-50192 for Kerberos Hub custom credential headers crossing redirects.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-m3cr-vc2j-pm27](https://github.com/advisories/GHSA-m3cr-vc2j-pm27) / CVE-2026-44454 | `github.com/coder/coder/v2` dotfiles registry module and Create Workspace `mode=auto` links | URL-controlled `param.dotfiles_uri` can cross from a workspace deep link into shell-expanded dotfiles setup during automatic workspace creation | Developer-platform assessments should treat workspace templates, dotfiles URLs, and auto-provision links as command surfaces, especially when one-click links skip explicit user confirmation. |
| [GHSA-gfhv-vqv2-4544](https://github.com/advisories/GHSA-gfhv-vqv2-4544) / CVE-2026-52726 | `dulwich >= 0.23.2, < 1.2.5` `porcelain.submodule_update` and `clone(..., recurse_submodules=True)` | repository-controlled `.gitmodules` plus gitlink path can materialize submodule content under the parent repository's `.git/hooks` directory | Git-library clients need the same submodule path validation as Git itself; prove with disposable repositories and inert hook markers only. |
| [GHSA-h5gx-45rj-2h5j](https://github.com/advisories/GHSA-h5gx-45rj-2h5j) / CVE-2026-50192 | Kerberos Hub agent upload client | custom `X-Kerberos-Hub-PrivateKey` / `X-Kerberos-Hub-PublicKey` headers can be forwarded to a cross-host redirect target because Go strips standard sensitive headers, not custom auth headers | Credential-forwarding tests must cover custom headers and redirect policy, not only `Authorization`/`Cookie`. |

### Workspace, submodule, and redirect harness

- Preconditions: disposable Coder or equivalent developer-workspace lab, throwaway Dulwich repository/client, mock Kerberos Hub endpoint, fake credentials, temp directories, and no production Git, workspace, camera, or Hub secrets.
- For Coder, create a workspace template or harness that logs the final dotfiles setup command. Compare a normal Create Workspace path with a `mode=auto` deep link carrying a shell-metacharacter canary in `param.dotfiles_uri`. Positive evidence is command construction/execution of only an inert marker inside the new disposable workspace.
- For Dulwich, build a malicious test repository where `.gitmodules` and the tree gitlink name a submodule path under `.git/hooks`; clone with `recurse_submodules=True` or run `submodule_update` in an isolated target directory. Positive evidence is a marker hook file written under the target repository's `.git/hooks` with executable mode, followed only by a harmless hook invocation if the program allows it.
- For Kerberos Hub, serve a mock Hub URL that first receives fake `X-Kerberos-Hub-*` headers and then returns same-origin and cross-origin redirects to an owned callback. Positive evidence is the fake custom header reaching the cross-origin endpoint.
- Negative controls: explicit workspace-create confirmation, dotfiles URI grammar validation before shell use, no shell interpolation for dotfiles setup, Dulwich `>= 1.2.5`, submodule paths rejected when absolute/outside-worktree/inside `.git`, and redirect-following that strips custom credential headers when scheme/host/port changes.
- Do not auto-create workspaces in shared production projects, run real dotfiles, clone untrusted repositories with real hooks enabled, forward live Kerberos Hub keys, or publish payloads beyond marker creation and fake-header capture.

### Additional reporting notes

- Lead with the crossed boundary: **workspace URL to shell-expanded dotfiles command**, **repository metadata to Git hook write**, or **custom Hub credential header to redirected authority**.
- Include versions, exact route or library entry point, argv/path/header decision table, confirmation state, and patched negative controls.
- Keep evidence synthetic: fake dotfiles URLs, temp hooks, fake private/public keys, owned redirectors, and disposable workspaces only.

## July 2 Grackle PowerLine worktree branch injection follow-up

A late July 2 GitHub Advisory Database entry adds another agent-orchestration command boundary: [GHSA-vv65-f55v-xm6g](https://github.com/advisories/GHSA-vv65-f55v-xm6g) for `@grackle-ai/runtime-sdk` / `@grackle-ai/powerline <= 0.132.1`. PowerLine `SpawnSession` request metadata can supply a task branch name that flows into Git worktree operations while the default executor invokes `git` with `shell:true`, turning a branch string into shell command construction on provisioned SSH hosts, Docker containers, or Codespaces.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-vv65-f55v-xm6g](https://github.com/advisories/GHSA-vv65-f55v-xm6g) | Grackle runtime SDK / PowerLine Git worktree executor | untrusted `req.branch` reaches `git worktree add -b <branch>` / related operations through a shell-backed executor instead of a safe argv vector | Agent orchestration assessments should treat task/session metadata as command input whenever it controls Git, package managers, shells, provisioned environments, or workspace bootstrap. |

### Grackle worktree command-boundary harness

- Preconditions: isolated Grackle/PowerLine lab, disposable provisioned host/container/Codespace, fake repository, no production SSH agent, Git credentials, workspace secrets, or long-lived agent state.
- Instrument the executor or wrap `git` to capture the final argv/string passed to the process launcher. Compare a normal branch name with a branch-name canary containing only inert metacharacters or a marker-write command targeted at a temp file.
- Positive evidence: the branch value is interpreted by a shell rather than passed as a literal Git ref. If execution is explicitly allowed in the lab, stop at creating a temp marker such as `/tmp/skillz-grackle-branch-canary`.
- Negative controls: executor uses `shell:false`, branch names pass strict Git ref grammar, leading dashes/metacharacters are rejected, a positional `--` is used where supported, and fixed package versions reject the canary.
- Do not run reverse shells, download payloads, read workspace files, use real dotfiles, or test on shared developer environments.

### Additional reporting notes

Lead with the crossed boundary: **agent task branch metadata to shell-backed Git worktree command**. Include package/version, RPC or orchestration route, normalized branch string, captured process-launch evidence, provisioned-environment type, inert marker result, and fixed-version negative control.

## Reviewed but not promoted here

- [GHSA-mjgf-xj26-9qf9](https://github.com/advisories/GHSA-mjgf-xj26-9qf9) is a webhook HMAC timing issue; useful for secure verification, but it did not add a distinct offensive workflow beyond existing signature-testing guidance.
- [GHSA-3ccm-4qq2-5wrp](https://github.com/advisories/GHSA-3ccm-4qq2-5wrp) is a panic on short ciphertext input and was not promoted because it is availability-focused.
- [GHSA-525m-7f82-2mf7](https://github.com/advisories/GHSA-525m-7f82-2mf7) is a Conform form-parser CPU exhaustion issue and was not promoted because it is resource-exhaustion focused.

## July 1 ORAS registry and layer-extraction update

Later GitHub Advisory Database entries extend the registry and artifact-boundary theme: [GHSA-xf85-363p-868w](https://github.com/advisories/GHSA-xf85-363p-868w) / CVE-2026-48978 for `oras-go` Bearer-token `realm` handling, and [GHSA-j6hm-v3x2-qv6j](https://github.com/advisories/GHSA-j6hm-v3x2-qv6j) for `land.oras:oras-java-sdk` symlink-following archive extraction.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-xf85-363p-868w](https://github.com/advisories/GHSA-xf85-363p-868w) / CVE-2026-48978 | `oras-go` auth client | registry-controlled `WWW-Authenticate: Bearer realm=` could steer token exchange to an untrusted endpoint | OCI client tests should include realm scheme/host validation and fake-token destination capture, not just registry-host allowlists. |
| [GHSA-j6hm-v3x2-qv6j](https://github.com/advisories/GHSA-j6hm-v3x2-qv6j) | `oras-java-sdk` archive utilities | tar/zip OCI layer extraction could create a symlink and then write through it outside the extraction root | Treat pulled artifact layers like untrusted archives; prove only with disposable extraction roots and outside-root canary files. |

### ORAS credential-realm and archive harness

- Preconditions: disposable OCI registry or mock registry, fake credentials/refresh tokens, owned token-service endpoint, temp extraction root, and no production image/package credentials.
- For `oras-go`, return a Bearer challenge whose `realm` points to an owned host, wrong scheme, sibling host, or path outside the expected registry trust domain. Positive evidence is a fake credential or refresh-token request reaching the owned endpoint.
- For `oras-java-sdk`, build a tar/zip layer that creates a symlink inside the extraction directory pointing to a temp outside directory, followed by a file entry that writes through the symlink. Positive evidence is a marker file under the outside directory.
- Negative controls: exact approved auth-realm policy, HTTPS-only token services, host/scheme pinning where configured, symlink rejection, realpath checks before every file write, and fixed-version denial.
- Do not reuse real registry tokens, publish malicious layers to public registries, overwrite shell startup files, or extract into developer home directories.

## July 1 MCP authorization and ORAS redirect/file-store follow-up

Late GitHub Advisory Database entries add adjacent MCP and OCI client boundaries: [GHSA-6gr2-qh89-hxwm](https://github.com/advisories/GHSA-6gr2-qh89-hxwm) / CVE-2026-50143 for Apify Actor MCP path authority injection, [GHSA-9c3v-684m-579c](https://github.com/advisories/GHSA-9c3v-684m-579c) for OpenClaw MCP SSE redirect authorization forwarding, [GHSA-jxpm-75mh-9fp7](https://github.com/advisories/GHSA-jxpm-75mh-9fp7) / CVE-2026-50151 and [GHSA-vh4v-2xq2-g5cg](https://github.com/advisories/GHSA-vh4v-2xq2-g5cg) for ORAS credential forwarding across registry-controlled `Location`/redirect targets, [GHSA-8xwf-rjm4-xvhv](https://github.com/advisories/GHSA-8xwf-rjm4-xvhv) / CVE-2026-50162 and [GHSA-fxhp-mv3v-67qp](https://github.com/advisories/GHSA-fxhp-mv3v-67qp) / CVE-2026-50163 for ORAS file-store and hardlink extraction escapes, and [GHSA-p9jg-fcr6-3mhf](https://github.com/advisories/GHSA-p9jg-fcr6-3mhf) / CVE-2026-53712 for SCRAM channel-binding downgrade handling.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-6gr2-qh89-hxwm](https://github.com/advisories/GHSA-6gr2-qh89-hxwm) / CVE-2026-50143 | `@apify/actors-mcp-server < 0.10.11` | Actor-controlled `webServerMcpPath` could be concatenated into a standby URL so `@host` userinfo syntax changes the final authority while bearer auth is still attached | MCP actor/tool metadata is a URL authority boundary; validate parsed scheme/host after joining, not just string prefixes. |
| [GHSA-9c3v-684m-579c](https://github.com/advisories/GHSA-9c3v-684m-579c) | `openclaw < 2026.6.5` | MCP SSE redirects could carry `Authorization` beyond the intended endpoint | Test MCP/SSE transports for redirect-follow behavior and header stripping with fake operator tokens. |
| [GHSA-jxpm-75mh-9fp7](https://github.com/advisories/GHSA-jxpm-75mh-9fp7) / CVE-2026-50151 | `oras-go < 2.6.1` blob upload | registry-controlled upload `Location` could redirect a credentialed `PUT` to another origin | Add cross-origin `Location` canaries to OCI upload clients and capture only fake `Authorization` values. |
| [GHSA-vh4v-2xq2-g5cg](https://github.com/advisories/GHSA-vh4v-2xq2-g5cg) | `oras-go < 2.6.1` registry requests | authenticated manifest/metadata redirects could forward origin registry credentials to a different host or port | Registry redirect handling needs same-origin checks and header-stripping negative controls, not just auth-realm validation. |
| [GHSA-8xwf-rjm4-xvhv](https://github.com/advisories/GHSA-8xwf-rjm4-xvhv) / CVE-2026-50162 | `oras-go < 2.6.1` file content store | lexical `workingDir` confinement could be bypassed through symlink path components in blob titles | Treat OCI annotation titles as filesystem write selectors; test symlink components with disposable roots. |
| [GHSA-fxhp-mv3v-67qp](https://github.com/advisories/GHSA-fxhp-mv3v-67qp) / CVE-2026-50163 | `oras-go <= 2.6.1` tar extraction | hardlink `Linkname` validation resolved relative targets differently from `link(2)`, allowing CWD-relative links into extracted layers | Extraction proofs should record resolved validation paths and final inode/link targets; never point links at real secrets. |
| [GHSA-p9jg-fcr6-3mhf](https://github.com/advisories/GHSA-p9jg-fcr6-3mhf) / CVE-2026-53712 | OnGres SCRAM client/common `<= 3.2` | unsupported certificate signature algorithms could turn required `SCRAM-SHA-256-PLUS` channel binding into non-channel-bound SCRAM | Database auth validation should include certificate-algorithm fixtures and mechanism negotiation transcripts. |

### MCP URL authority and redirect harness

- Preconditions: disposable MCP server/client harness, fake Apify/OpenClaw tokens, owned callback host, and no real actor, Gateway, cloud, or operator secrets.
- For Actor MCP URL construction, seed an actor definition or mock API response whose MCP path contains userinfo/authority-shifting characters such as `@owned.example/mcp`; record the parsed final URL and whether a fake bearer token reaches the owned host.
- For SSE redirects, serve an MCP endpoint that responds with a same-origin control redirect and a cross-origin redirect. Positive evidence is a fake `Authorization` header on the cross-origin request.
- Negative controls: path values must be relative paths beginning with `/`, final URLs must be parsed and pinned to the expected origin, and redirect-following must strip credentials when scheme/host/port changes.

### ORAS redirect and filesystem follow-up harness

- Preconditions: loopback registry/mock registry, fake registry config credentials, temp extraction root, temp outside directory, and no production OCI credentials or developer home paths.
- Test blob upload `Location`, manifest redirects, and Bearer realms separately. For each, compare same-origin and cross-origin destinations and record whether fake auth material is forwarded.
- For file-store writes, create a symlink component under the working directory pointing to a temp outside directory, then use a blob title that should remain inside the work root.
- For hardlink extraction, keep the process CWD under a disposable directory containing only a marker file; build a tar layer whose relative `Linkname` can show CWD-vs-extraction-root resolution without touching sensitive files.
- Negative controls: strict scheme/host/port equality for credential forwarding, redirect target allowlists when cross-origin storage is explicitly supported, realpath checks before every write/link, symlink rejection, and fixed ORAS versions.

### SCRAM channel-binding downgrade harness

- Preconditions: lab PostgreSQL/SCRAM harness or unit test, disposable credentials, and test certificates using both traditional `WITH`-named algorithms and modern algorithms such as Ed25519.
- Configure the client policy to require channel binding, then record advertised mechanisms, selected mechanism, channel-binding data/hash result, and final auth decision.
- Positive evidence is a required-channel-binding client silently authenticating without channel binding after certificate-hash derivation fails.
- Do not run MITM tests against production databases, capture real passwords, or downgrade live database sessions.

## July 5 TidGi and AD_Miner import/cache follow-up

The July 5 GitHub Advisory Database wave adds two adjacent operator patterns for tools that ingest repository or cache material: [GHSA-vv7r-8584-6pm6](https://github.com/advisories/GHSA-vv7r-8584-6pm6) / CVE-2026-14722 for TidGi-Desktop Git repository import, and [GHSA-2rqq-j7w9-23vp](https://github.com/advisories/GHSA-2rqq-j7w9-23vp) / CVE-2026-14723 for AD_Miner cache handling.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-vv7r-8584-6pm6](https://github.com/advisories/GHSA-vv7r-8584-6pm6) / CVE-2026-14722 | TidGi-Desktop `<= 0.13.0` Git repository import / sub-wiki loading | repository-controlled wiki/sub-wiki content can cross from import metadata into code execution in the desktop process | Desktop knowledge-base and note-taking imports should be treated like package installs when they execute loaders, plugins, scripts, or generated wiki code. |
| [GHSA-2rqq-j7w9-23vp](https://github.com/advisories/GHSA-2rqq-j7w9-23vp) / CVE-2026-14723 | AD-Security AD_Miner `1.9.0` cache handler | a local cache path supplied as `sys.argv[1]` can reach unsafe deserialization in analysis code | Recon-tool assessments should include cache/project restore paths, not only network inputs, because imported assessment artifacts often come from third parties. |

### Repository import and cache-deserialization harness

- Preconditions: isolated desktop/recon-tool lab VM, disposable TidGi workspace, affected AD_Miner version, throwaway Git repositories/cache files, no real browser profiles, AD dumps, notes, client workspaces, or operator credentials.
- For TidGi, import only an owned repository with a harmless marker in the sub-wiki/loading path. Positive evidence should be an inert marker action such as writing a temp file or logging a canary string from the desktop process.
- For AD_Miner, invoke the affected analysis path with a synthetic cache file designed to prove deserialization reachability using only an inert marker class or blocked-policy trace. Keep the cache path under a temp directory you control.
- Negative controls: patched TidGi behavior, import mode that disables active loaders/plugins by default, signed or trusted workspace prompts, AD_Miner cache parsing that uses safe formats, and deserialization allowlists that reject unexpected classes.
- Do not import untrusted public repositories into a real notes workspace, execute shell payloads, read local notes or credential stores, load real BloodHound/AD_Miner assessment artifacts, or publish payloads beyond marker creation.

### Additional reporting notes

Lead with the crossed boundary: **Git repository import to desktop wiki code execution** or **recon-tool cache file to unsafe deserialization**. Include tool version, import/CLI path, synthetic repo/cache layout, marker-only evidence, and fixed-version or safe-mode negative controls.

## July 6 Coder workspace, app-proxy, identity, and AI Bridge follow-up

The July 6 GitHub Advisory Database wave adds a broad Coder control-plane cluster: [GHSA-5wg6-jmq2-53pw](https://github.com/advisories/GHSA-5wg6-jmq2-53pw) / CVE-2026-55438, [GHSA-7qw2-f75v-62f7](https://github.com/advisories/GHSA-7qw2-f75v-62f7) / CVE-2026-55437, [GHSA-84rm-42xw-mx52](https://github.com/advisories/GHSA-84rm-42xw-mx52) / CVE-2026-55436, [GHSA-wqxv-w64v-5wh6](https://github.com/advisories/GHSA-wqxv-w64v-5wh6) / CVE-2026-55435, [GHSA-jqj2-x4c5-jfxm](https://github.com/advisories/GHSA-jqj2-x4c5-jfxm) / CVE-2026-55433, [GHSA-x9qq-2qh5-8rxf](https://github.com/advisories/GHSA-x9qq-2qh5-8rxf) / CVE-2026-55432, [GHSA-v54h-cp2w-9x4g](https://github.com/advisories/GHSA-v54h-cp2w-9x4g) / CVE-2026-55431, [GHSA-5g4w-3vw9-478w](https://github.com/advisories/GHSA-5g4w-3vw9-478w) / CVE-2026-55430, [GHSA-wrq8-fcv5-8hvp](https://github.com/advisories/GHSA-wrq8-fcv5-8hvp) / CVE-2026-55428, [GHSA-9rjw-3gwp-f59v](https://github.com/advisories/GHSA-9rjw-3gwp-f59v) / CVE-2026-55429, [GHSA-mcqq-fqgf-rxwm](https://github.com/advisories/GHSA-mcqq-fqgf-rxwm) / CVE-2026-55427, [GHSA-29xf-69gq-m9jx](https://github.com/advisories/GHSA-29xf-69gq-m9jx) / CVE-2026-55077, [GHSA-9r87-mvcw-x35f](https://github.com/advisories/GHSA-9r87-mvcw-x35f) / CVE-2026-55075, and [GHSA-75vm-6w67-gwvp](https://github.com/advisories/GHSA-75vm-6w67-gwvp) / CVE-2026-55076.

These advisories are operator-relevant because Coder-style developer platforms concentrate several reusable boundaries in one place: wildcard workspace-app hostnames, browser CORS decisions, app session cookies, agent-supplied network routes, provisioner-completed app metadata, CLI-generated SSH config, OIDC account linking, and AI proxy tokens. Keep proofs to disposable deployments, synthetic users, fake IdP claims, fake API/provider tokens, owned app subdomains, inert workspace apps, and packet/decision tables. Do not collect real prompts, session tokens, SSH config, workspace files, or customer app responses.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-5wg6-jmq2-53pw](https://github.com/advisories/GHSA-5wg6-jmq2-53pw) | Coder subdomain workspace-app CORS | a hostname segment that parses as a workspace UUID could resolve by ID while CORS trusted the unverified username in the hostname | Test wildcard app routing with owner/user mismatches and UUID-looking workspace segments before trusting same-owner CORS results. |
| [GHSA-5g4w-3vw9-478w](https://github.com/advisories/GHSA-5g4w-3vw9-478w) | Workspace app proxy host resolution | client-supplied `X-Forwarded-Host` could steer app routing while same-site app cookies authorized the request | App-proxy reviews should include browser-set forwarding headers unless an upstream trusted-proxy boundary strips them. |
| [GHSA-x9qq-2qh5-8rxf](https://github.com/advisories/GHSA-x9qq-2qh5-8rxf) | Sub-agent app registration | agent RPC app sharing level could exceed the template's `MaxPortSharingLevel` | Treat agent-created app metadata as policy input; verify public/owner sharing clamps on every app-registration path. |
| [GHSA-wrq8-fcv5-8hvp](https://github.com/advisories/GHSA-wrq8-fcv5-8hvp) | Tailnet coordinator | authenticated agents could advertise arbitrary WireGuard `AllowedIPs` prefixes | Workspace-agent network proofs should compare authenticated agent identity to every advertised route, not only assigned addresses. |
| [GHSA-9rjw-3gwp-f59v](https://github.com/advisories/GHSA-9rjw-3gwp-f59v) | Provisioner `CompleteJob` / app upsert | caller-supplied app IDs could rebind another workspace's app row to the attacker's agent | Provisioner APIs are authority boundaries; test ID ownership before updates under privileged provisioner contexts. |
| [GHSA-v54h-cp2w-9x4g](https://github.com/advisories/GHSA-v54h-cp2w-9x4g) | `coder open app` external app URLs | template/workspace-controlled URLs could receive `$SESSION_TOKEN` substitution before opening arbitrary schemes/hosts | CLI helpers that expand tokens into app URLs need destination pinning; prove with fake tokens and owned callback URLs only. |
| [GHSA-mcqq-fqgf-rxwm](https://github.com/advisories/GHSA-mcqq-fqgf-rxwm) | `coder config-ssh` | server-supplied SSH config options and hostname suffixes could inject newline-delimited directives such as `ProxyCommand` | Developer CLI config generation should be tested as local code execution surface when server values cross into `~/.ssh/config`. |
| [GHSA-9r87-mvcw-x35f](https://github.com/advisories/GHSA-9r87-mvcw-x35f) / [GHSA-75vm-6w67-gwvp](https://github.com/advisories/GHSA-75vm-6w67-gwvp) | OIDC email fallback and `email_verified` parsing | absent, non-boolean, or unverified email claims could be treated as verified and linked to existing users by email | Identity reviews should fuzz claim type, absence, and subject-linking state, not just happy-path IdP responses. |
| [GHSA-29xf-69gq-m9jx](https://github.com/advisories/GHSA-29xf-69gq-m9jx) | Password reset route | `user-admin` could reset an owner password without the current password | Role-boundary testing should include protected higher-tier roles, not just route access for peer users. |
| [GHSA-84rm-42xw-mx52](https://github.com/advisories/GHSA-84rm-42xw-mx52) / [GHSA-wqxv-w64v-5wh6](https://github.com/advisories/GHSA-wqxv-w64v-5wh6) | AI Bridge proxy | default outbound TLS verification was skipped, and suspended users' unexpired API keys could still reach LLM proxy endpoints | AI proxy tests should record TLS validation posture, proxy-env behavior, account-status checks, and token revocation state with fake provider keys. |
| [GHSA-7qw2-f75v-62f7](https://github.com/advisories/GHSA-7qw2-f75v-62f7) / [GHSA-jqj2-x4c5-jfxm](https://github.com/advisories/GHSA-jqj2-x4c5-jfxm) | Agent logs and devcontainer recreate | workspace-controlled logs rendered as HTML, and read-only workspace roles could trigger destructive recreate | Use harmless DOM markers and route-decision tables; avoid destructive container recreation outside disposable labs. |

### Coder app-proxy and agent-boundary harness

- Preconditions: isolated Coder deployment, wildcard app hostname configured when testing subdomain routing, two synthetic users/workspaces, inert workspace apps that return only canary strings, a controllable upstream proxy config, and no production sessions or workspace content.
- For subdomain CORS, generate app URLs where the username segment and resolved workspace UUID intentionally disagree. Positive evidence is a credentialed browser request whose CORS decision trusts the hostname username instead of the resolved workspace owner.
- For `X-Forwarded-Host`, serve an attacker-owned app that issues a same-site `fetch()` with a forged forwarding header pointing at a victim canary app. Positive evidence is routing to the victim canary response solely because the header was trusted.
- For sub-agent app sharing, register an app through the sub-agent path with `PUBLIC` sharing against a template that allows only owner access. Positive evidence is unauthenticated access to an inert canary app despite policy.
- For tailnet `AllowedIPs`, use a modified lab agent or coordinator harness to advertise another synthetic agent's prefix. Positive evidence is only a route table or WireGuard peer-config mismatch; do not intercept real terminals, IDEs, or app traffic.
- Negative controls: patched Coder release lines, trusted-proxy configuration that strips browser-supplied forwarding headers, CORS decisions based on authoritative workspace owner, sharing-level clamps on every app-create path, and route prefixes derived from authenticated agent identity.

### Coder CLI, identity, and AI Bridge harness

- Preconditions: disposable client VM, fake Coder server or lab deployment, fake OIDC provider, fake provider/API tokens, no real SSH config or long-lived sessions, and backups of any test dotfiles.
- For `coder open app`, define an external app URL pointing to an owned callback with a fake `$SESSION_TOKEN` marker. Positive evidence is token substitution only in the lab callback; never use a real session token.
- For `coder config-ssh`, serve settings containing newline or directive canaries and write to a temporary SSH config path if the CLI supports it, or use a disposable home directory. Positive evidence is an injected directive appearing as a separate parsed SSH option.
- For OIDC, build a two-user decision table covering verified boolean `true`, boolean `false`, string `"false"`, absent `email_verified`, and existing subject links. Positive evidence is account linking or login when the email should fail closed.
- For AI Bridge, use fake provider keys and a local TLS harness with a self-signed or wrong-host certificate. Positive evidence is accepted HTTPS when verification should fail, or a suspended synthetic user's token still reaching the LLM proxy route.
- Negative controls: strict app URL scheme/host allowlists, no token substitution outside trusted frontend destinations, SSH option character filtering, fail-closed `email_verified` coercion, subject-bound account linking, verified TLS transports, and active-user checks for every AI Bridge authorization path.

### Additional reporting notes

Lead with the crossed boundary: **workspace hostname to CORS owner**, **browser header to app routing**, **agent route metadata to tailnet prefixes**, **provisioner app ID to cross-workspace rebinding**, **workspace/template URL to CLI token leak**, **server setting to local SSH config directive**, **OIDC claim type to account link**, or **AI proxy token/TLS state to provider traffic**. Include feature preconditions, role or user-interaction requirements, synthetic canary values, route/config decision tables, and patched negative controls.

## July 6 late Coder cross-agent redirect follow-up

A later July 6 GitHub Advisory Database entry adds [GHSA-qrwj-vh9x-gw5v](https://github.com/advisories/GHSA-qrwj-vh9x-gw5v), covering Coder workspace-agent API redirect handling that could cross from one agent context into another agent's file-read or file-write surface.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-qrwj-vh9x-gw5v](https://github.com/advisories/GHSA-qrwj-vh9x-gw5v) | Coder workspace agent API redirects | redirect-follow behavior can carry an agent API request into a different workspace-agent authority and expose cross-agent file read/write effects | Developer-platform tests should include per-hop authority checks for agent-local APIs, not only the initial workspace, app, or agent selector. |

### Cross-agent redirect harness

- Preconditions: disposable Coder deployment, two synthetic workspaces/agents, fake file contents, owned callback or mock agent endpoints, and no real workspace files, SSH keys, tokens, prompts, or customer source trees.
- From an authorized lab client, send only marker-only file-read/write requests through the affected agent API path and make one hop redirect to a sibling synthetic agent authority.
- Positive evidence: the request follows the redirect and reads or writes a canary file under the sibling agent context despite being authorized for the original agent.
- Negative controls: patched build, redirect-follow disabled for file APIs, same scheme/host/port/agent identity enforced after every redirect, and a sibling-agent redirect rejected before file access.
- Report this as **workspace-agent redirect to cross-agent file authority**. Include route, original and redirected agent identifiers, redirect status/location, canary-only path, and the fixed-version decision table.
