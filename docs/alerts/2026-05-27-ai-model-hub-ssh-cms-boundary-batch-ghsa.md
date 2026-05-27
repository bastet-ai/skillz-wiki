# AI model hub, AsyncSSH, and Automad boundary batch (GHSA, 2026-05-27)

**Signal:** A late May 27 GitHub Advisory batch adds several replayable operator boundaries that are useful beyond generic patch awareness: AI/ML package trust pivots through model loading and validator installation, unauthenticated distributed-training KVStore deserialization, SSH authorized-keys path traversal, and unauthenticated CMS administrator secret exposure.

Promoted items:

- `GHSA-pq2f-x424-6fjm` / `CVE-2026-31239`: `mamba-ssm` `MambaLMHeadModel.from_pretrained()` loads Hugging Face `pytorch_model.bin` files with `torch.load()` without `weights_only=True`, letting a malicious model repository execute Python during model load.
- `GHSA-r6hf-g5x6-7pv9` / `CVE-2026-31233`: Guardrails AI `guardrails hub install` executes a manifest-controlled `post_install` script path from Hub package metadata, turning validator installation into a package-trust RCE boundary.
- `GHSA-mf8f-x4r3-jm8c` / `CVE-2026-31234`: Horovod's unauthenticated KVStore HTTP server accepts attacker-supplied data over `PUT`; workers later call `cloudpickle.loads()` on that data during coordination.
- `GHSA-g794-3fmp-753h` / `CVE-2026-45309`: AsyncSSH `2.22.0` expands `AuthorizedKeysFile` `%u` with the raw pre-auth username, allowing traversal usernames to select an authorized-keys file outside the intended directory when the server uses patterns such as `authorized_keys/%u`.
- `GHSA-xm76-r88j-vm3g` / `CVE-2026-45332`: Automad `2.0.0-alpha.1` through `2.0.0-beta.27` leaves the setup `/_api/user-collection/create-first-user` endpoint reachable after initialization and returns serialized administrator data, including bcrypt password hashes; beta 27 can also expose TOTP secrets.

Use this only in authorized testing. Keep proofs scoped to lab repositories, disposable package names, local training clusters, test SSH servers, or program-approved staging CMS instances. Do not publish malicious model/package artifacts to public hubs, poison shared training infrastructure, authenticate to SSH services you are not authorized to test, or brute-force recovered hashes.

## Operator checklist

### 1. AI model-loading trust boundary: `mamba-ssm`

Where to look:

- Research notebooks, inference services, fine-tuning jobs, CI benchmarks, demo apps, and agent pipelines that call `MambaLMHeadModel.from_pretrained()` on user-selected or remotely configured model IDs.
- `mamba-ssm` versions `<= 2.2.6`.
- Places where a model name can be influenced through a request parameter, config file, environment variable, dataset metadata, prompt/tool instruction, or benchmark manifest.
- Workflows that treat Hugging Face model repositories as data-only and do not pin revisions or review artifacts.

Safe validation path:

1. Confirm that the target path loads `pytorch_model.bin` via `mamba-ssm`, not a different loader that already restricts pickle execution.
2. In a local lab or private organization namespace, create a harmless marker model artifact that demonstrates code execution by writing a canary file or printing a unique marker.
3. For a real program, prefer non-executing evidence first: package version, source call path, controllable model ID, and absence of revision pinning. Only run the marker artifact if the scope explicitly allows code-execution validation.
4. Capture whether the process has secrets, network access, GPU worker privileges, or mounted datasets; those boundaries determine impact.

Reporting heuristic: strong reports show **untrusted model selection reaches a pickle-backed model loader**. Include the exact call path, model source control point, package version, revision policy, and a harmless lab proof showing why the model artifact is an execution boundary rather than just data.

### 2. Guardrails Hub validator install boundary

Where to look:

- LLM applications, CI workflows, notebooks, and agent sandboxes that run `guardrails hub install` from user-provided docs, config, prompts, recipes, or project templates.
- `guardrails-ai` versions `<= 0.6.7`.
- Internal validator registries or mirrors that proxy upstream Hub metadata without validating manifest fields.
- Automation that installs validators during application startup, benchmark setup, or pull-request tests.

Safe validation path:

1. Reproduce in an isolated virtual environment with a private/test validator package and a benign `post_install` marker.
2. Verify whether the installer constructs and executes the `post_install` path directly from package metadata.
3. For target validation, avoid publishing harmful or confusing public packages. Use a private package, local mirror, or source review when possible.
4. Record the triggering command, package source, manifest field, execution user, working directory, and available secrets.

Reporting heuristic: frame this as **package metadata becoming an installer command boundary**. The best reports show a realistic path from user/project-controlled validator selection to code execution during installation.

### 3. Horovod KVStore deserialization in distributed training

Where to look:

- Horovod `<= 0.28.1` training jobs exposing the KVStore HTTP server across pod, node, or tenant boundaries.
- Kubernetes jobs, HPC clusters, notebook platforms, or MLOps schedulers where worker coordination ports are reachable by other users or workloads.
- Job templates that do not isolate training networks or that reuse predictable host/port assignments.

Safe validation path:

1. Map Horovod coordination endpoints from an authorized test network using version/banner/config evidence where available.
2. In a disposable cluster, demonstrate that an unauthenticated `PUT` can pre-seed a key that a worker later reads and deserializes with `cloudpickle.loads()`.
3. Use a benign payload in lab only, such as writing a marker inside a disposable container. For shared or production clusters, stop at unauthenticated write/read influence unless explicit RCE proof is approved.
4. Capture network reachability from neighboring workloads, timing requirements, and whether the worker trusts the KVStore as a single source of coordination data.

Reporting heuristic: high-impact reports connect **cross-workload KVStore write access** to worker-side deserialization. Include cluster topology, namespace/tenant boundary, Horovod version, and why an attacker can win the race before legitimate values are written.

### 4. AsyncSSH `AuthorizedKeysFile %u` traversal

Where to look:

- AsyncSSH servers pinned to `2.22.0`.
- Configs using OpenSSH-compatible per-user key patterns such as `AuthorizedKeysFile authorized_keys/%u`.
- Applications that accept arbitrary SSH usernames and do not reject `/`, `\\`, or `..` before AsyncSSH expands `%u`.
- Hosts where an attacker can place a readable authorized-keys-format file outside the intended key directory, for example through upload, build artifact, temp-file, or shared workspace features.

Safe validation path:

1. Confirm the exact AsyncSSH version and `AuthorizedKeysFile` pattern.
2. In a local harness or authorized staging server, create an attacker-controlled public-key file outside the intended directory.
3. Attempt public-key authentication with a traversal-shaped username that resolves `%u` to that file.
4. Avoid testing against production SSH surfaces unless the program explicitly authorizes authentication-bypass attempts; otherwise report source/config evidence plus a local reproduction.

Reporting heuristic: strong reports show **username-as-path input crosses into public-key trust selection**. Provide the denied control login, accepted traversal login in a lab/staging environment, config snippet, and file-placement primitive.

### 5. Automad setup endpoint administrator-secret exposure

Where to look:

- Public Automad `2.0.0-alpha.1` through `2.0.0-beta.27` installations.
- Internet-facing beta deployments, preview sites, headless CMS pilots, or staging instances that were initialized but still expose setup APIs.
- `2.0.0-beta.27` specifically when assessing TOTP-secret exposure.

Safe validation path:

1. Fingerprint Automad and version where permitted before touching setup endpoints.
2. Send only the minimal request needed to confirm whether `/_api/user-collection/create-first-user` remains reachable after setup.
3. If the response contains hashes or TOTP material, do not brute-force, reuse, or disclose secrets beyond the report. Redact most of the hash/secret and preserve enough structure to prove exposure.
4. Capture whether the response includes all administrator records and absolute config paths.

Reporting heuristic: impactful reports show **post-install unauthenticated access to administrator credential material**. Include endpoint reachability, version, redacted response fields, and whether TOTP secrets are present.

## Non-signal this hour

Reviewed but not promoted as standalone Skillz guidance:

- `GHSA-9frc-8383-795m` / `CVE-2026-45305`, `GHSA-4qpc-3hr4-r2p4` / `CVE-2026-45304`, and `GHSA-c2p3-7m5p-cv8x` / `CVE-2026-45133` Symfony YAML parser ReDoS, alias expansion, and recursion-depth hardening. They are useful parser-hardening context but mostly availability/resource-exhaustion issues without a new offensive validation workflow for the current taxonomy.
- CISA KEV remained catalog `2026.05.27` with Nx Console, TanStack, Daemon Tools Lite, LiteSpeed cPanel plugin, and older entries already reflected or not converted into fresh Skillz operator guidance this pass.
- PortSwigger Research stayed on the Top 10 web hacking techniques of 2025.
- Trail of Bits stayed on the already-covered zizmor GitHub Actions static-analysis article.
- ProjectDiscovery RSS stayed on already-covered Neo / Nuclei / DAST proof-loop material; `/blog/rss.xml` still returned 404 while `/blog/rss` remained reachable.
- GitHub Security Blog remained GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.

## Sources

- [mamba Hugging Face model deserialization advisory (`GHSA-pq2f-x424-6fjm`)](https://github.com/advisories/GHSA-pq2f-x424-6fjm)
- [Guardrails AI Hub install code injection advisory (`GHSA-r6hf-g5x6-7pv9`)](https://github.com/advisories/GHSA-r6hf-g5x6-7pv9)
- [Horovod KVStore deserialization advisory (`GHSA-mf8f-x4r3-jm8c`)](https://github.com/advisories/GHSA-mf8f-x4r3-jm8c)
- [AsyncSSH authorized-keys traversal advisory (`GHSA-g794-3fmp-753h`)](https://github.com/advisories/GHSA-g794-3fmp-753h)
- [Automad administrator hash and TOTP exposure advisory (`GHSA-xm76-r88j-vm3g`)](https://github.com/advisories/GHSA-xm76-r88j-vm3g)
