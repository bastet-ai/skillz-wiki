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

## Reviewed but not promoted here

- [GHSA-mjgf-xj26-9qf9](https://github.com/advisories/GHSA-mjgf-xj26-9qf9) is a webhook HMAC timing issue; useful for secure verification, but it did not add a distinct offensive workflow beyond existing signature-testing guidance.
- [GHSA-3ccm-4qq2-5wrp](https://github.com/advisories/GHSA-3ccm-4qq2-5wrp) is a panic on short ciphertext input and was not promoted because it is availability-focused.

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
