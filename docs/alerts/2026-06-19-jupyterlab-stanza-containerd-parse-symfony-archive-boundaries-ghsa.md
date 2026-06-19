# JupyterLab Git, NLP model, container runtime, backend API, and archive boundary checks

Source: hourly offensive-security scan, 2026-06-19. Primary entries: GitHub advisories [GHSA-f962-v9hr-pfg5](https://github.com/advisories/GHSA-f962-v9hr-pfg5), [GHSA-436q-jwfr-rm2h](https://github.com/advisories/GHSA-436q-jwfr-rm2h), [GHSA-v5jw-96jm-7h2c](https://github.com/advisories/GHSA-v5jw-96jm-7h2c), [GHSA-xhf5-7wjv-pqxp](https://github.com/advisories/GHSA-xhf5-7wjv-pqxp), [GHSA-33vj-92qq-66hc](https://github.com/advisories/GHSA-33vj-92qq-66hc), [GHSA-rgh6-rfwx-v388](https://github.com/advisories/GHSA-rgh6-rfwx-v388), [GHSA-cvxm-645q-p574](https://github.com/advisories/GHSA-cvxm-645q-p574), [GHSA-p84r-h6rx-f2xr](https://github.com/advisories/GHSA-p84r-h6rx-f2xr), [GHSA-wmwx-jr2p-4j4r](https://github.com/advisories/GHSA-wmwx-jr2p-4j4r), [GHSA-75v4-m273-5j49](https://github.com/advisories/GHSA-75v4-m273-5j49), [GHSA-v8x7-r927-cc93](https://github.com/advisories/GHSA-v8x7-r927-cc93), [GHSA-7wqv-xjf3-x35v](https://github.com/advisories/GHSA-7wqv-xjf3-x35v), [GHSA-4m4j-hmqq-3gxm](https://github.com/advisories/GHSA-4m4j-hmqq-3gxm), [GHSA-34w5-c283-j9fg](https://github.com/advisories/GHSA-34w5-c283-j9fg), [GHSA-38x5-rcv4-xf7x](https://github.com/advisories/GHSA-38x5-rcv4-xf7x), [GHSA-946h-jp5c-8fvh](https://github.com/advisories/GHSA-946h-jp5c-8fvh), and [GHSA-q6rc-2cgv-63h7](https://github.com/advisories/GHSA-q6rc-2cgv-63h7).

This batch is durable because each item exposes a repeatable trust-boundary test rather than a one-off product alert: shared Git repository metadata crossing into a privileged notebook UI, case-insensitive filesystem aliases bypassing Jupyter path exclusions, NLP model checkpoints falling back from safe deserialization to unsafe pickle, Kubernetes node restore paths trusting checkpoint or image metadata, Parse Server API route and relation controls diverging from operator assumptions, Symfony UX browser-state signatures and AJAX gates missing context, autocomplete endpoints becoming SQL `LIKE` oracles, and 7z symlink chains writing outside an extraction root.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-f962-v9hr-pfg5 | `jupyterlab-git` diff history | repository-controlled renamed filenames were inserted into Git diff UI HTML and could drive browser-session actions in JupyterLab | Treat shared repositories as active UI input for notebook environments; validate filename rendering with harmless DOM markers and never run untrusted repos with real notebook tokens or terminals. |
| GHSA-436q-jwfr-rm2h | `jupyterlab-git` `excluded_paths` | admin path exclusions used case-sensitive matching while macOS/Windows filesystems resolve case variants to the same directory | On case-insensitive hosts, test path security controls with canonical and case-varied forms; prove only with synthetic excluded directories. |
| GHSA-v5jw-96jm-7h2c | Stanza model loaders | a safe `torch.load(..., weights_only=True)` failure caused the same model file to be reloaded through unsafe pickle deserialization | Review AI/NLP model-loading code for safe-load fallbacks; keep proof to inert checkpoint canaries in disposable model caches. |
| GHSA-xhf5-7wjv-pqxp | containerd CRI labels and restart monitor | image `LABEL` metadata reached host-side plugin consumers such as restart-monitor `binary://` loggers | In Kubernetes/runtime reviews, trace image metadata from pull time into node-local executors; use local lab clusters and inert host markers only. |
| GHSA-33vj-92qq-66hc | containerd checkpoint restore CDI annotations | checkpoint image metadata preserved CDI annotations and could request host CDI device edits during restore | Validate checkpoint restore as a node privilege boundary, especially where CDI is enabled; do not request real GPUs, devices, or host mounts outside a lab. |
| GHSA-rgh6-rfwx-v388 | containerd checkpoint restore logs | checkpoint `container.log` restoration followed symlinks, making `kubectl logs` a host-file read sink | Use disposable host canaries to test checkpoint-to-log boundaries; never read kubelet credentials, pod logs, or production node files. |
| GHSA-cvxm-645q-p574 | containerd checkpoint import image refs | checkpoint import could poison local image tags, influencing later pods using cached tags and weak pull policies | Check whether restore/import paths can mutate node-local image identity; prove with throwaway tags and lab namespaces only. |
| GHSA-p84r-h6rx-f2xr | Parse Server `/batch` | outer-route `routeAllowList` checks were not re-applied to batch sub-requests | Treat batch/multiplex endpoints as alternate routers; compare direct route denial with equivalent batch sub-request handling. |
| GHSA-wmwx-jr2p-4j4r | Parse Server `$relatedTo` | relation queries exposed membership even when the relation field or owning object was hidden by ACL/`protectedFields` | Add relation-membership oracles to Parse/API tests where private groups, block lists, or account-resource links are modeled as relations. |
| GHSA-75v4-m273-5j49 | Parse Server `/login` and `/verifyPassword` | denied controlled re-fetches fell back to raw user rows and could disclose MFA or protected fields | Test authentication endpoints as data-return surfaces, not only login gates; evidence should be redacted field presence with disposable users. |
| GHSA-v8x7-r927-cc93 and GHSA-7wqv-xjf3-x35v | Parse Server file uploads | blocklist extension parsing missed dangerous content types for non-standard, compound, or trailing-dot filenames on content-type-preserving storage adapters | Pair filename extension checks with served `Content-Type` evidence on owned storage; use harmless SVG/HTML markers and an isolated upload origin. |
| GHSA-4m4j-hmqq-3gxm | Symfony UX LiveComponent | `Accept` was treated as CSRF protection even though browsers can set it as a CORS-safelisted header | Test AJAX-only gates with browser-fetch constraints, SameSite cookie settings, and cross-origin preflight behavior rather than header presence alone. |
| GHSA-34w5-c283-j9fg | Symfony UX LiveComponent hydrator | HMACs covered prop values but not component name or slot context, allowing signed state replay across compatible components | For signed browser state, verify that signatures bind identity, slot, route, and intent, not just sorted values. |
| GHSA-38x5-rcv4-xf7x | Symfony UX child components | client-controlled child component tags reached HTML output during LiveComponent re-rendering | Treat re-render JSON as template input; prove with non-executing tag/attribute markers unless a separate same-origin path is in scope. |
| GHSA-946h-jp5c-8fvh | Symfony UX Autocomplete | unescaped SQL `LIKE` wildcards let public autocomplete endpoints become broad matchers or blind entity-column oracles | Add `%`, `_`, and escape-character probes to autocomplete/entity search testing; capture row-count or boolean differences with seeded canaries. |
| GHSA-q6rc-2cgv-63h7 | `py7zr` extraction | symlink chains inside 7z archives could cause later extracted files to write outside the destination directory | Include archive symlink-resolution tests in upload/import pipelines; extract only into disposable roots with outside canary directories. |

## Operator triage

1. **Find the alternate input path.** The vulnerable surface is often not the primary route: Git history diff rendering, batch sub-requests, relation operators, checkpoint restore/import, LiveComponent re-render JSON, autocomplete search, or archive extraction.
2. **Record the privilege boundary.** State exactly what crosses the boundary: repo filename to notebook browser, checkpoint metadata to node restore, image label to host plugin, signed prop blob to another component, relation query to hidden membership, or symlink entry to outside destination.
3. **Use synthetic canaries.** Seed disposable files, users, relations, repos, model files, images, archives, and Kubernetes namespaces. Do not collect notebook tokens, model secrets, kubelet credentials, production logs, MFA secrets, customer records, or real host files.
4. **Separate browser, direct-client, and same-origin pivots.** Symfony and Parse findings depend on specific CORS, cookie, storage, and API-client assumptions. Capture those preconditions before claiming broad impact.
5. **Do not generalize memory-safety-only items.** Several adjacent Oj advisories in the same wave are parser memory-safety bugs; skip them unless a target-specific exploit chain or fuzzing workflow is authorized.

## Replayable validation boundaries

### Shared Git repository to JupyterLab UI

- Build a lab JupyterLab instance with `jupyterlab-git`, a disposable token, and a repository that contains only marker files.
- For UI rendering, create commits with renamed files whose names include harmless text markers that would visibly break escaping if rendered as HTML. Use screenshot/DOM evidence only; do not open terminals or execute commands as proof.
- For path exclusions, configure `excluded_paths` for a synthetic directory and compare exact-case and case-varied Git API/UI requests on a case-insensitive host.
- Negative controls: patched `jupyterlab-git`, a case-sensitive filesystem, escaped filename rendering, and canonical path matching that rejects every case variant.

### Model-loader safe-fallback checks

- Inventory model-loading calls that claim to use safe deserialization, especially wrappers around PyTorch `weights_only=True`, safetensors, model hub downloads, and shared cache paths.
- Create a disposable model/cache directory with an inert checkpoint canary that triggers the safe-loader rejection path without executing real payloads.
- Positive evidence is code-path proof or a marker-only harness showing that the loader catches a safe-load exception and retries with unsafe pickle against the same untrusted file.
- Never place malicious model files in shared production caches, notebook homes, CI artifacts, or inference workers with credentials.

### Kubernetes checkpoint and image metadata boundaries

- Use a local lab cluster or single-node sandbox with no production credentials, no sensitive CDI specs, and no real workload namespaces.
- For checkpoint restore, inspect whether checkpoint metadata can influence CDI annotations, restored log paths, or imported image references. Use synthetic CDI names, fake image tags, and outside canary files.
- For image-label flows, trace labels from image config into container annotations, runtime plugin inputs, log-driver/restart-monitor settings, or node-local command wrappers. Proof should be an inert marker, not a real host command.
- Negative controls: patched containerd, CDI disabled or no matching host CDI spec, checkpoint restore unavailable to the tested role, and pull policies/tags that cannot be poisoned by local cache state.

### Parse Server API control drift

- Map every route firewall or allowlist decision twice: the direct REST path and any batch/multiplex wrapper that can dispatch to the same internal route.
- Seed a lab Parse app with disposable users, private relation objects, protected fields, and MFA-like canary fields. Test anonymous, authenticated, and expected privileged clients.
- For upload checks, test filename extension, trailing dot, compound extension, supplied `Content-Type`, storage adapter behavior, and final response headers from the served file URL.
- Keep evidence to route status deltas, relation membership canaries, redacted field names, and harmless rendered upload markers.

### Symfony UX browser-state and query oracles

- For LiveComponent, capture the exact browser headers, SameSite/cookie settings, CORS policy, signed prop blobs, component names, child slots, and re-render JSON accepted by the endpoint.
- Attempt cross-component or cross-slot replay only with lab values that change visible marker text or a harmless boolean flag.
- For autocomplete, seed entities with known marker fields and test literal search terms against `%`, `_`, and escape-character variants. Record row-count or match/no-match deltas.
- Do not treat wildcard broad matching as SQL injection; report it as an autocomplete/query-oracle boundary unless arbitrary SQL construction is independently proven.

### Archive symlink extraction

- Extract only in a disposable directory with one outside canary directory specifically created for the test.
- Include archive entries that create symlinks and then later regular files below those symlinks; inspect resolved paths before and after extraction.
- Positive evidence is a marker file written outside the extraction root. Do not target shell startup files, SSH keys, application config, package caches, or service directories.
- Negative controls: patched `py7zr`, extraction code that rejects symlinks, extraction code that resolves every path after symlink creation, and callers that unpack in an isolated container or mount namespace.

## Reporting notes

- Name the crossed boundary precisely: **repository filename to notebook UI execution**, **case-insensitive path alias to excluded Git directory read**, **safe model load fallback to unsafe pickle**, **checkpoint metadata to node device/log/image state**, **image label to host-side runtime plugin**, **batch sub-request to route firewall bypass**, **relation operator to hidden membership oracle**, **authentication endpoint to raw protected fields**, **upload filename/content-type mismatch to active stored content**, **CORS-safelisted header to CSRF gate**, **unbound HMAC to cross-component state replay**, **client child tag to trusted HTML**, **SQL wildcard to autocomplete oracle**, or **archive symlink chain to outside write**.
- Include version, filesystem, storage adapter, browser cookie/CORS state, Kubernetes/containerd configuration, and patch-level evidence because these findings are precondition-heavy.
- Keep exploit validation scoped to authorized lab targets and synthetic data; the useful operator artifact is the decision table and trust-boundary proof, not live secret access.
