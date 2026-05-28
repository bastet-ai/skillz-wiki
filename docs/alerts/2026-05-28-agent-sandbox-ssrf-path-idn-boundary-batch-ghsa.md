# Agent sandbox, research SSRF, path-read, and IDN boundary batch (GHSA, 2026-05-28)

**Signal:** GitHub Advisory Database published a late May 28 batch with reusable offensive-operator value across AI-agent sandbox confinement, local research fetchers, repository-controlled CLI files, and hostname canonicalization. The durable lesson is to test whether the validating component and the executing component agree on the same security boundary: sandbox IPC policy versus user-session services, URL parser versus HTTP client, repo-local path policy versus filesystem reads, and IDN polyfill versus native `intl` behavior.

Promoted items:

- `GHSA-27vp-2mmc-vmh3` / `CVE-2026-47128`: `nono-cli < 0.55.0` sandbox profiles can allow Linux sandbox escape through local Unix-domain sockets and the per-user D-Bus / systemd control plane, letting an agent-confined process spawn unsandboxed sibling processes with the launcher user's authority.
- `GHSA-g23j-2vwm-5c25` / `CVE-2026-46526`: `local-deep-research < 1.6.10` validates URLs with one parser and fetches with `requests`, allowing backslash / userinfo parser differentials such as a URL that validates as a public host but is fetched from loopback or another restricted address.
- `GHSA-x6p3-76f2-xxvh` / `CVE-2026-47144`: `shamefile <= 0.1.6` can read files outside the repository when `shame next` processes attacker-controlled `shamefile.yaml`, disclosing content one line at a time to the invoking user's terminal.
- `GHSA-2xf4-cg6j-vhgq` / `CVE-2026-46644`: `symfony/polyfill-intl-idn` and `symfony/polyfill` `>= 1.17.1, < 1.38.1` accept malformed `xn--` labels that PHP native `ext-intl` rejects, creating unsafe hostname equivalence that can feed blacklist bypasses, inconsistent URL parsing, and SSRF allowlist drift.

Reviewed but not promoted standalone:

- `GHSA-rpc6-9c4p-j5cg` / `CVE-2026-8766`: `@kilocode/cli` `KILO_CONFIG_CONTENT` information disclosure has AI-coding-tool relevance, but the public advisory lacks enough stable mechanics for a distinct Skillz operator workflow beyond general environment/config-secret review.
- `GHSA-j76w-p754-g2w7` / `CVE-2026-4054`: Mattermost proxied-image SVG response-body validation is mainly client-side DoS.
- `GHSA-hw87-6jcq-9f8q` / `CVE-2026-4053`: Mattermost post-edit-time drift for non-message fields may matter in app abuse reviews, but it is not a high-signal standalone exploit-path lesson for this wiki.

Use this only in authorized tests. Keep proofs minimal: use disposable sandbox users, tester-owned callback hosts, harmless local listener ports, non-sensitive marker files, and lab-only hostnames. Do not use sandbox escapes to modify real files, probe cloud metadata, read secrets, or alter production repositories unless the engagement explicitly provides a safe harness.

## Operator checklist

### 1. Agent sandbox escape through local IPC policy drift

Where to look:

- Linux hosts using `nono-cli < 0.55.0` to confine coding agents such as Aider, Claude Code, OpenCode, or similar tools.
- Profiles that intentionally allow shell/build tools while relying on Landlock/seccomp to reduce filesystem and network blast radius.
- Environments where the invoking user has sensitive filesystem, network, Git credential, SSH-agent, or browser-session authority outside the sandbox.

Safe validation path:

1. Confirm the `nono-cli` version and active sandbox profile.
2. Start from a disposable project directory and a disposable test user, not the operator's real home directory.
3. From inside the sandbox, attempt a benign user-session IPC action that should be blocked by the sandbox model, such as creating a marker file in a pre-approved directory outside the allowed working tree through a user-service launch path.
4. Verify whether the marker appears outside the sandbox boundary and whether the spawned process runs without the expected Landlock/seccomp constraints.
5. Stop at marker proof. Do not enumerate home directories, network services, credentials, or SSH/browser agents.

Evidence to capture:

- `nono-cli` version, profile name, and allowed path/network assumptions.
- The sandbox command transcript with payload redacted to the marker action.
- Before/after evidence that the marker was written outside the intended sandbox boundary.
- Explanation of the launcher user's authority that the escaped sibling process inherited.

Reporting heuristic: frame this as **local IPC mediation drift in an AI-agent sandbox**. Strong reports show the sandbox policy claims to confine arbitrary agent-invoked shell tools, but local user-session IPC lets those tools regain the full launcher-user authority.

### 2. Research fetcher SSRF through parser/client disagreement

Where to look:

- `local-deep-research < 1.6.10` deployments, internal research assistants, and agent workflows that let users submit URLs for retrieval.
- URL validation wrappers that parse with `urllib.parse.urlparse()` or equivalent but fetch with a different HTTP stack.
- Fetchers that run from a privileged workstation, CI runner, internal network, or AI workbench with access to services the requester cannot reach directly.

Safe validation path:

1. Confirm the package version and identify the `safe_get` / URL-fetch call path.
2. Stand up a tester-owned public callback and a local lab-only listener on loopback or an approved internal canary host.
3. Submit a URL variant that the validator classifies as public but the HTTP client resolves/fetches as the restricted host because of parser differentials around backslashes, userinfo, or host separators.
4. Verify only callback or canary reachability. Do not request cloud metadata, admin interfaces, localhost secrets, or production-only ports.
5. Record whether redirects, DNS rebinding, IPv6 forms, or encoded delimiters are also validated and fetched by different components, but keep each test to approved endpoints.

Evidence to capture:

- Version and source line / request path showing distinct validation and fetch components.
- The submitted URL with sensitive hostnames replaced by canary domains or local lab addresses.
- Validator-observed host versus HTTP-client destination proof.
- Callback logs, source IP / runner identity, and response handling behavior.

Reporting heuristic: the strongest reports prove **parser differential SSRF**, not merely that SSRF might exist: the preflight validator records an allowed host while the request library connects to a restricted host.

### 3. Repository-controlled `shamefile.yaml` arbitrary file read

Where to look:

- Developer or CI workflows running `shame next` on pull requests, untrusted repositories, template repos, or agent-modified branches.
- `shamefile <= 0.1.6` across the npm, pip, and Rust package ecosystems.
- Automation where terminal output is logged to CI artifacts, chatops transcripts, issue comments, or agent memory.

Safe validation path:

1. Confirm the `shamefile` version and the command path that processes repository-controlled `shamefile.yaml`.
2. In a disposable repository, create a non-sensitive canary file outside the repository root.
3. Add a `shamefile.yaml` entry that attempts to reference only that canary file through traversal.
4. Run `shame next` and verify whether a line from the outside canary appears in terminal output.
5. Do not target shell history, SSH keys, tokens, environment files, package credentials, or real source outside the test repository.

Evidence to capture:

- Package ecosystem and version.
- Repository path, canary path, and redacted `shamefile.yaml` snippet.
- Command output showing one-line canary disclosure.
- Where that output would be stored or exposed in the real workflow.

Reporting heuristic: prioritize findings where **a contributor-controlled repo file causes the operator, CI runner, or agent to print content from outside the repo**, especially when logs are published back to the attacker-controlled pull request or issue.

### 4. Symfony IDN polyfill unsafe hostname equivalence

Where to look:

- PHP apps using `symfony/polyfill-intl-idn` or `symfony/polyfill` `>= 1.17.1, < 1.38.1` on runtimes without native `ext-intl`.
- SSRF defenses, redirect allowlists, webhook URL allowlists, tenant-domain checks, OAuth callback host checks, and link-safety filters that canonicalize hostnames before comparison.
- Mixed fleets where development, CI, or some containers use the polyfill while production or adjacent services use native `ext-intl`.

Safe validation path:

1. Confirm whether the code path is using the Symfony polyfill rather than native `ext-intl`.
2. Create a lab allowlist / denylist comparison using malformed `xn--` labels that the polyfill decodes into ASCII-only output but native `ext-intl` rejects.
3. Test whether the application treats the malformed label as equivalent to an allowed or denied hostname.
4. If the path controls fetching, use a tester-owned domain and callback endpoint; do not target internal metadata, admin panels, or third-party services.
5. Compare behavior across containers with and without `ext-intl` to show environment-dependent policy drift.

Evidence to capture:

- Dependency version and whether native `ext-intl` is loaded.
- Input hostname, polyfill-normalized output, and native `ext-intl` rejection/error proof.
- The application decision that changes because of the unsafe equivalence.
- Any callback evidence from tester-owned infrastructure if URL fetching is involved.

Reporting heuristic: frame this as **hostname canonicalization drift**. High-value reports connect the IDN mismatch to a concrete policy boundary such as SSRF allowlist bypass, redirect/callback trust, tenant-domain ownership, or phishing-link safety checks.

## References

- [nono sandbox escape advisory (`GHSA-27vp-2mmc-vmh3`)](https://github.com/advisories/GHSA-27vp-2mmc-vmh3)
- [local-deep-research SSRF parser-differential advisory (`GHSA-g23j-2vwm-5c25`)](https://github.com/advisories/GHSA-g23j-2vwm-5c25)
- [shamefile arbitrary file-read advisory (`GHSA-x6p3-76f2-xxvh`)](https://github.com/advisories/GHSA-x6p3-76f2-xxvh)
- [Symfony IDN polyfill unsafe-equivalence advisory (`GHSA-2xf4-cg6j-vhgq`)](https://github.com/advisories/GHSA-2xf4-cg6j-vhgq)
