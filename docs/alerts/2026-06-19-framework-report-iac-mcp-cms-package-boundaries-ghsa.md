# Framework, report, IaC, MCP, CMS, and package-control boundary checks

Source: hourly offensive-security scan, 2026-06-19. Primary entries: GitHub advisories [GHSA-c7jm-38gq-h67h](https://github.com/advisories/GHSA-c7jm-38gq-h67h), [GHSA-pr33-38xx-6r26](https://github.com/advisories/GHSA-pr33-38xx-6r26), [GHSA-m4w9-hjfw-vwj4](https://github.com/advisories/GHSA-m4w9-hjfw-vwj4), [GHSA-jrpc-7vxp-69p6](https://github.com/advisories/GHSA-jrpc-7vxp-69p6), [GHSA-4mr2-fg2p-w63c](https://github.com/advisories/GHSA-4mr2-fg2p-w63c), [GHSA-gx93-m64w-5m6h](https://github.com/advisories/GHSA-gx93-m64w-5m6h), [GHSA-82cg-3hv7-74gc](https://github.com/advisories/GHSA-82cg-3hv7-74gc), [GHSA-rpj2-4hq8-938g](https://github.com/advisories/GHSA-rpj2-4hq8-938g), [GHSA-jr33-mw75-7j8f](https://github.com/advisories/GHSA-jr33-mw75-7j8f), [GHSA-f9m7-vc86-p6jj](https://github.com/advisories/GHSA-f9m7-vc86-p6jj), [GHSA-g5qx-h5f3-mp2f](https://github.com/advisories/GHSA-g5qx-h5f3-mp2f), [GHSA-c55v-343g-5xff](https://github.com/advisories/GHSA-c55v-343g-5xff), [GHSA-4936-9hrh-qqpw](https://github.com/advisories/GHSA-4936-9hrh-qqpw), [GHSA-fcw4-wwqm-m8cf](https://github.com/advisories/GHSA-fcw4-wwqm-m8cf), [GHSA-wfqx-gjrf-g28r](https://github.com/advisories/GHSA-wfqx-gjrf-g28r), [GHSA-v75r-vx73-82pj](https://github.com/advisories/GHSA-v75r-vx73-82pj), [GHSA-x845-2f78-7v36](https://github.com/advisories/GHSA-x845-2f78-7v36), and [GHSA-cw25-2p92-7f75](https://github.com/advisories/GHSA-cw25-2p92-7f75).

This batch is durable because the advisories expose reusable operator checks: framework defaults crossing into authentication, cookie, cryptographic, and host-routing assumptions; report artifacts and cassettes crossing into local browser or deserializer trust; unauthenticated MCP/OAuth context leaks; sitemap/archive parsers and transport archives crossing filesystem or resource boundaries; CMS/editor-controlled labels crossing into JavaScript or CLI execution; and Kubernetes/IaC/package-manager metadata crossing into cluster-admin, package-verification, shell, package-install, or DNSSEC trust decisions.

## June 23 Bedrock AgentCore package installer update

[GHSA-6rfw-mq36-jm8h](https://github.com/advisories/GHSA-6rfw-mq36-jm8h) / CVE-2026-12530 extends the package-control pattern to AWS Bedrock AgentCore's Python SDK. The advisory says `install_packages()` in the Code Interpreter client built a `pip install` shell command from caller-provided package-name arguments and allowed crafted pip flags such as `--index-url` and `-r`, letting an authenticated remote user redirect package resolution to an attacker-controlled package index or expose arbitrary sandbox files/environment variables. Treat agent package-install helpers as command and dependency-resolution boundaries, even when they accept values that look like package names rather than shell commands.

## June 23 OpenTofu provider-cache symlink update

[GHSA-wcmj-x466-56mm](https://github.com/advisories/GHSA-wcmj-x466-56mm) extends the IaC package-install pattern to OpenTofu provider installation. A repository-controlled symlink under `.terraform/providers` could be followed during `tofu init`, causing provider package contents to be written outside the working tree when the operator initializes an attacker-controlled root module. Treat IaC dependency caches as filesystem write boundaries: a project checkout can contain symlinks and package selectors before the first successful init.

## June 30 Prefect GitHub repository reference update

[GHSA-cw25-2p92-7f75](https://github.com/advisories/GHSA-cw25-2p92-7f75) / CVE-2026-3515 extends the repository-control pattern to Prefect's `prefect-github` integration. The advisory says the `GitHubRepository` block concatenated the user-controlled `reference` value into a `git clone` command string before `shlex.split()` parsing, allowing crafted references to become git command-line options such as `-c`. Treat workflow-orchestrator repository references as command-argument boundaries: branch, tag, SHA, and pull-request fields may be operator-controlled strings that reach clone/fetch helpers before any project code runs.

## July 1 MCP Toolbox DNS-rebinding update

[GHSA-7pf3-8xx7-rvhf](https://github.com/advisories/GHSA-7pf3-8xx7-rvhf) / CVE-2026-9739 extends the MCP/OAuth context exposure pattern to Google MCP Toolbox for Databases. The advisory says the SSE initialization handler retained `Access-Control-Allow-Origin: *`, creating a DNS-rebinding path for browser-originated access to Toolbox SSE under MCP specification v2024-11-05 even when `allowed-origins` and `allowed-hosts` were intended to enforce MCP security guidelines.

Operator validation boundaries:

- Preconditions: isolated Toolbox instance, fake database tools/credentials, owned rebinding domain or local host-header harness, and no production databases attached.
- Compare direct host access, allowed host/origin, disallowed host/origin, and rebinding-style browser requests against harmless MCP routes such as tool listing or a canary read-only tool.
- Positive evidence is browser-originated SSE/session bootstrap access from an origin/host combination that policy should deny, with only fake token or tool metadata in scope.
- Negative controls: fixed version, strict `Origin` and `Host` checks before SSE initialization, no wildcard CORS on authenticated transports, and rejection after DNS answer changes.
- Do not run write-capable database tools, query real schemas, capture real MCP tokens, or expose Toolbox to the public internet for testing.

## July 16 Ansible Galaxy role dependency update

[GHSA-w8p5-mx5w-cpqj](https://github.com/advisories/GHSA-w8p5-mx5w-cpqj) extends the package-control pattern to `ansible-galaxy role install`. The advisory says `ansible-core` processed dependency specifications from a role's `meta/requirements.yml` and failed to neutralize argument delimiters in `src`, allowing a malicious role author to inject Git configuration flags during role dependency installation. Treat Ansible role metadata as a repository-controlled command-argument boundary: installing a role can cause its declared dependencies to reach `git` before playbook execution starts.

Operator validation boundaries:

- Use only disposable Ansible workspaces, owned throwaway roles, fake credentials, and local or owned Git remotes. Never run probes from an operator workstation profile that contains production inventory, SSH agents, vault files, cloud credentials, or private collections.
- Model `meta/requirements.yml` as untrusted dependency metadata. Exercise normal role sources, option-shaped sources, config-flag-shaped values, and owned callback remotes while capturing the argument vector, resolver log, or marker-only callback.
- Positive evidence is that a dependency `src` value is parsed as a Git option or configuration flag rather than as data naming a repository. Stop at parser/control-plane confusion; do not fetch hooks that execute real commands, expose credential helpers, or clone sensitive repositories.
- Negative controls: patched `ansible-core` versions, dependency source values passed after `--`, strict source validation, and installations from roles whose dependency metadata cannot influence Git options.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-c7jm-38gq-h67h | http4k DigestAuth | default nonce verifier accepted replayed digest challenges | Treat framework auth helpers as security-sensitive defaults; replay captured digest responses only in lab sessions with disposable credentials. |
| GHSA-pr33-38xx-6r26 | http4k cookie storage | client cookie jar ignored RFC 6265 domain/path scoping | Test client-side session jars and reverse-proxy helpers with sibling domains, path collisions, and same-name cookie precedence. |
| GHSA-m4w9-hjfw-vwj4 | http4k `HmacSha256.hash` | HMAC-named helper computed an unkeyed SHA-256 digest | Verify signed webhooks, callbacks, and tokens bind a secret key by negative-controling wrong-key signatures, not by function names. |
| GHSA-jrpc-7vxp-69p6 | http4k `reverseProxy()` | default host matcher used substring containment instead of exact host matching | Add `trusted.example.com.evil.tld` and sibling-host canaries to reverse-proxy host allowlist tests. |
| GHSA-4mr2-fg2p-w63c | Traefik Kubernetes Ingress NGINX provider | missing or unreadable auth-secret resolution could fail open | Compare Ingress auth behavior with valid, missing, unreadable, and cross-namespace secrets in a lab namespace. |
| GHSA-gx93-m64w-5m6h | Allure Report renderer | ANSI helper/status trace fields reached stored HTML rendering | Treat CI/test-report artifacts as untrusted web content; prove with harmless DOM markers in disposable reports. |
| GHSA-82cg-3hv7-74gc | Allure Report HTTP server | report server path handling could read outside the served report root | Test local report viewers with synthetic outside canary files only; never read developer home, CI, or token files. |
| GHSA-rpj2-4hq8-938g | VCR.py cassettes | cassette YAML files could reach unsafe deserialization | Treat recorded HTTP fixtures from issues, PRs, and shared repos as code; proof should be a marker-only YAML harness in a disposable checkout. |
| GHSA-jr33-mw75-7j8f | dbt MCP Server | unauthenticated OAuth context endpoint could expose platform tokens | Map MCP/SSE/HTTP endpoints that reveal session bootstrap or OAuth context; evidence should use fake tokens or redacted field presence. |
| GHSA-f9m7-vc86-p6jj | `go.qbee.io/transport` tar extraction | symlink chains in archives could write one level outside destination | Reuse archive symlink-resolution tests with temp roots and outside marker directories. |
| GHSA-g5qx-h5f3-mp2f | TinaCMS browser/editor flows | cross-origin `postMessage` handlers and rich-text URL sanitization could cross into stored XSS/session control | Validate editor message origins and rich-text URL schemes with owned origins and non-executing markers before claiming account impact. |
| GHSA-c55v-343g-5xff | Craft CMS `actionResourceJs` | Host header poisoning influenced generated JavaScript and outbound fetch behavior | Pair Host-header SSRF tests with script-generation sinks; use owned callback hosts and benign JS markers only. |
| GHSA-4936-9hrh-qqpw | `@tinacms/cli` Forestry migration | user-controlled YAML labels reached migration code generation/execution | Treat CMS migration/import labels as codegen input; validate with inert marker declarations in disposable projects. |
| GHSA-fcw4-wwqm-m8cf | Grafana Operator | namespace-admin dashboard JSONNet library filename could influence cluster-scoped behavior | Test operator CR fields as privilege boundaries between namespace admin and cluster admin in a throwaway cluster. |
| GHSA-wfqx-gjrf-g28r | Crossplane package install | signature verification trusted mutable tag state across a TOCTOU window | Verify signed-package flows pin immutable digests; prove only with owned registries and benign package markers. |
| GHSA-v75r-vx73-82pj | `@cyclonedx/cyclonedx-npm` | unsanitized `--workspace` reached shell execution | Fuzz package-manager workspace and path arguments as shell boundaries; use inert commands and disposable repos. |
| GHSA-x845-2f78-7v36 | Blocky DNSSEC | validation cache state could be polluted across DNSSEC decisions | Test resolver cache scope with lab domains and mock resolvers; avoid targeting real recursive infrastructure. |
| GHSA-6rfw-mq36-jm8h / CVE-2026-12530 | AWS Bedrock AgentCore Python SDK `install_packages()` | package-name arguments crossed into `pip install` flags, package-index selection, and sandbox file/environment exposure | Test agent code-interpreter package installers with pip-flag canaries, owned package indexes, and disposable sandbox files; do not exfiltrate live credentials or run untrusted packages on production workers. |
| GHSA-wcmj-x466-56mm | OpenTofu provider installer | root-module-controlled `.terraform/providers` symlinks could redirect provider package writes outside the working tree during `tofu init` | Test untrusted IaC checkouts for cache symlink following with disposable outside directories and inert provider packages; never target home directories, credentials, or shared plugin caches. |
| GHSA-cw25-2p92-7f75 / CVE-2026-3515 | Prefect `GitHubRepository` block | repository `reference` value crossed into `git clone` option parsing after shell-string construction and `shlex.split()` | Test orchestration Git integrations with branch/tag/reference option canaries, dry-run clone logging, and owned callback remotes; never expose real workflow tokens, SSH keys, deployment secrets, or production work pools. |
| [GHSA-7pf3-8xx7-rvhf](https://github.com/advisories/GHSA-7pf3-8xx7-rvhf) / CVE-2026-9739 | MCP Toolbox for Databases SSE transport | wildcard CORS on SSE initialization could allow DNS-rebinding access despite intended host/origin policy | Test MCP HTTP/SSE transports with browser-origin, Host, DNS-rebinding, and harmless tool-list canaries before trusting local-only deployment assumptions. |
| [GHSA-w8p5-mx5w-cpqj](https://github.com/advisories/GHSA-w8p5-mx5w-cpqj) | `ansible-core` / `ansible-galaxy role install` | role dependency `src` metadata could inject Git configuration flags during dependency install | Test untrusted Ansible roles as package-manager inputs where metadata reaches Git arguments before playbook code runs. |

## Operator triage

1. **Find the default that changes the boundary.** Framework helpers often look safe by name: digest auth, cookie storage, HMAC helpers, reverse proxies, and Ingress auth annotations all need negative controls.
2. **Trace artifact-to-runtime flow.** Report files, VCR cassettes, CMS migrations, package metadata, and archives are often treated as passive artifacts until a viewer, CLI, or operator reconciler executes them.
3. **Separate token presence from token theft.** For MCP/OAuth context endpoints, use fake or disposable tokens and redacted field names. Do not collect live dbt, cloud, CI, or user tokens.
4. **Prove with canaries, not production secrets.** Use owned callback hosts, synthetic outside files, disposable repositories, throwaway Kubernetes namespaces, lab package registries, and mock DNS zones.
5. **Skip availability-only parser issues unless tied to a boundary.** Sitemap decompression/entity expansion items in the same wave are useful for parser hardening but were not promoted here without a stronger offensive validation path.

## Replayable validation boundaries

### Framework auth, crypto, cookie, and host-routing defaults

- Build a minimal http4k lab app or client harness with disposable credentials, a controlled reverse-proxy backend, and owned sibling hostnames.
- Digest auth: capture a legitimate challenge/response and replay it against the same route. Positive evidence is replay acceptance where nonce freshness should fail.
- Cookie storage: seed same-name cookies across parent/sibling domains and narrower/wider paths, then record which value the client sends.
- HMAC helpers: compute signatures with a correct key, wrong key, and no key. Positive evidence is acceptance of a digest that does not depend on the secret.
- Host matching: test exact host, suffix host, prefix host, embedded host, and punycode/case variants. Keep effects to backend selection or visible marker routing.

### CI reports, cassettes, and local artifact viewers

- Generate disposable Allure reports and VCR.py cassettes in a local project with no secrets in environment variables, shell history, or fixture files.
- For report rendering, place harmless ANSI/status/trace markers that would show whether escaping failed. Do not attempt browser session theft.
- For path traversal, create a synthetic file outside the report root and request only that canary path.
- For cassettes, use marker-only YAML deserialization harnesses; do not execute shell payloads, install hooks, or run shared fixtures in production repos.

### MCP/OAuth context exposure

- Inventory MCP servers for unauthenticated HTTP, SSE, streamable-HTTP, and context/bootstrap endpoints.
- Configure fake platform tokens or disposable project tokens, then request context routes as anonymous, low-privilege, and intended clients.
- Positive evidence is redacted token-shaped field presence, scope metadata, or tenant identifiers returned without expected authentication.
- Do not publish or store live dbt Platform tokens, database credentials, model credentials, or cloud secrets.

### Kubernetes, operators, and signed-package supply chain

- Use a throwaway Kubernetes cluster with no production CRDs, service-account tokens, or real namespaces.
- For Traefik auth secrets, compare normal auth prompts against missing, renamed, unreadable, and cross-namespace secrets. Evidence is route status and auth challenge deltas.
- For Grafana Operator, test whether namespace-scoped dashboard fields can steer cluster-scoped JSONNet/library resolution. Use marker dashboards only.
- For Crossplane, run an owned registry with mutable tags and immutable digests. Positive evidence is package content changing after verification but before install; never push malicious providers to public registries.

### CMS/editor and CLI import codegen

- Use lab Craft/TinaCMS projects with owned domains and editor accounts.
- Host-header tests should route to owned callbacks and generated JavaScript markers; do not probe internal metadata services.
- `postMessage` tests should enumerate accepted origins, message types, and state-changing handlers with marker payloads.
- Migration/import tests should feed YAML labels that create inert marker declarations or visible no-op output, not shell commands or credential reads.

### Archive and package-manager argument boundaries

- Extract only into disposable temp directories with a pre-created outside canary directory one level up.
- Include archive entries that create symlinks first and later write through them; record resolved path before and after extraction.
- For package-manager CLIs, test workspace names, paths, and dependency source fields containing option-shaped or shell-shaped canaries in a disposable repo.
- Never target shell startup files, SSH keys, package caches, project secrets, or production build agents.

### IaC provider-cache symlink boundaries

- Use only disposable OpenTofu/Terraform-style root modules and a temp directory as the outside write canary. Do not run probes from a real infrastructure repository or a directory containing credentials, state, backend config, or production `.terraform` caches.
- Pre-create a `.terraform/providers/...` path component as a symlink to the temp outside canary directory, then run `tofu init` with an inert provider source/version under a lab user.
- Positive evidence is provider package content or marker files written through the symlink into the canary directory, plus path-resolution logs and OpenTofu version. Do not point symlinks at home directories, shell startup files, cloud config, SSH keys, CI workspaces, or shared plugin caches.
- Negative controls: patched versions remove or reject mismatched symlinks before installation, and provider content remains under the working tree or configured global cache only.

### Workflow orchestrator Git-reference argument boundaries

- Use a disposable Prefect workspace or a local harness around `prefect-github`'s `GitHubRepository.get_directory()` / `aget_directory()` path. Do not point probes at production work pools, deployment repos, or environments with real cloud, GitHub, SSH, CI, or database credentials.
- Seed only owned throwaway repositories and fake credentials. Configure the reference field with normal branches/tags first, then option-shaped canaries such as values beginning with `-c`, `--config`, `--upload-pack`, `--reference`, or path-like values that should be rejected as references rather than parsed as git options.
- Positive evidence is the argument vector, dry-run log, owned callback hit, or inert marker effect showing the reference was interpreted as a git option instead of a branch/tag/SHA. Stop at proof of parser/control-plane confusion; do not run remote commands, fetch attacker-controlled hooks, read credential helpers, or clone sensitive repositories.
- Negative controls: references are passed as structured arguments after `--`, constrained to valid ref syntax, or resolved through API lookups before clone/fetch; option-prefixed refs fail closed and GitLab/Bitbucket-style list-based command construction remains unaffected.

### Ansible Galaxy role dependency argument boundaries

- Use a disposable Ansible install and a throwaway role whose `meta/requirements.yml` declares only owned dependencies. Do not run against production automation repositories, real inventories, CI runners, SSH agents, or directories containing vault files.
- First install a benign dependency role from an owned Git remote and record the expected `ansible-galaxy role install` resolver behavior.
- Then replace the dependency `src` with option-shaped Git canaries, configuration-flag canaries, and owned callback remotes that should be rejected or treated as literal repository data.
- Positive evidence is an argument vector, resolver trace, owned callback, or inert marker showing dependency metadata changed Git invocation semantics. Avoid payloads that execute hooks, alter global Git config, read credential helpers, or run arbitrary commands on a real workstation.
- Negative controls: patched `ansible-core` release candidates or fixed branches reject delimiter/option injection, normalize dependency sources before Git invocation, and preserve legitimate `git+https`, SSH, and Galaxy dependency forms.

### Agent code-interpreter package installers

- Use a disposable Bedrock AgentCore Code Interpreter sandbox or a local mock of the SDK call path; never run installer probes in a production agent runtime with real credentials, mounted repos, or customer data.
- Seed a synthetic sandbox file and fake environment variable with non-sensitive marker values, plus an owned throwaway package index or local package server.
- Exercise package arguments that look like ordinary package names, pip options, requirements-file selectors, alternate indexes, direct URLs, and path-like values. Positive evidence is installer argument parsing, index selection, or marker-only file/environment exposure that contradicts the expected package-name-only contract.
- Prefer mock sinks and dry-run logging where available. If package resolution is required, serve only inert packages from an owned index and capture resolver requests, not secrets.
- Negative controls: arguments are parsed as structured package identifiers, option prefixes are rejected, requirements-file and index flags cannot be supplied by remote callers, and sandbox environment/file values are not reflected through install errors or package metadata.

### DNSSEC validation-cache scope

- Use lab authoritative zones, mock resolvers, or isolated Blocky instances.
- Compare valid, bogus, unsigned, and sibling-zone answers while recording cache keys and validation state transitions.
- Positive evidence is a cached validation decision crossing names, record types, clients, or upstream resolver contexts where it should not.
- Avoid sending crafted DNSSEC pollution tests through enterprise or ISP recursive resolvers.

## Reporting notes

- Name the crossed boundary precisely: **digest-auth replay default**, **cookie-scope confusion**, **unkeyed signature helper**, **substring host allowlist**, **Ingress auth-secret fail-open**, **report artifact to trusted browser**, **report path to outside file**, **cassette YAML to code execution**, **MCP context to OAuth token**, **archive symlink to outside write**, **editor message/rich-text to trusted CMS UI**, **Host header to generated JavaScript/SSRF**, **migration label to codegen execution**, **namespace CR field to cluster-admin behavior**, **mutable package tag to verified install**, **workspace argument to shell**, **agent package argument to pip flag/index/file exposure**, **IaC provider-cache symlink to outside write**, **workflow Git reference to clone option**, **Ansible role dependency source to Git option**, or **DNSSEC validation cache to sibling decision**.
- Include exact versions, default configuration, negative controls, and the disposable canary values used. The useful artifact is the trust-boundary decision table, not sensitive data exposure.
