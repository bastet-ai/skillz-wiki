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
