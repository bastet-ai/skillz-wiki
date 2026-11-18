# vLLM and Anyquery boundary checks

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-3ww4-5jv9-j5gm](https://github.com/advisories/GHSA-3ww4-5jv9-j5gm) / CVE-2026-47155 for vLLM artifact pin decay and [GHSA-j9rx-rppg-6hh4](https://github.com/advisories/GHSA-j9rx-rppg-6hh4) / CVE-2026-47253 for Anyquery plugin-cache traversal.

This batch is durable because it turns advisory details into repeatable operator checks for AI inference artifact integrity and SQL-exposed filesystem deletion helpers. Use it for authorized assessments of model-serving platforms, AI/ML deployment pipelines, and self-hosted data-query services.

## What changed

- **vLLM artifact pin decay**, deployments that pass `--revision` or `--code-revision` can still resolve behavior-affecting artifacts from an unpinned/default revision. Reported boundaries include external `auto_map` dynamic module imports without `code_revision`, GGUF direct-file downloads without `revision`, BGE-M3 side weights with `revision=None`, Kimi image/audio processors, and same-repository subfolder weights/config that are not bound to the reviewed pin.
- **Anyquery plugin-cache traversal deletion**, the SQL scalar function `clear_plugin_cache(plugin)` joins the caller-controlled plugin name under the Anyquery cache root and calls `os.RemoveAll`. `..` segments can escape the intended plugin-cache directory when a bearer-token holder can submit SQL through `/v1/query` or another query path that exposes the function.

## Operator triage

1. **Map model-serving entry points:** inventory vLLM CLI flags, Helm values, container args, CI/CD variables, notebook launchers, and UI fields that accept model IDs, model paths, revisions, or code-revision pins.
2. **Separate reviewed pins from runtime resolution:** for vLLM, compare the intended reviewed revision with every artifact actually fetched at startup: primary weights, config, tokenizer/processor files, GGUF files, side weights, and same-repository subfolders.
3. **Check who can submit model paths:** prioritize platforms where lower-privileged users, project maintainers, CI jobs, or tenant workflows can influence model repositories loaded by a higher-privileged serving process.
4. **Locate Anyquery HTTP/query exposure:** identify Anyquery instances with `/v1/query` reachable beyond localhost, bearer tokens shared with low-privilege users, LLM query helpers enabled, or plugin-management functions callable from SQL.
5. **Classify deletion impact by process privileges:** Anyquery impact depends on what the service account can remove. Strong findings show escape from `$XDG_CACHE_HOME/anyquery/plugins/` to a synthetic directory outside the plugin cache, not destruction of production data.

## Replayable validation boundaries

### vLLM artifact pin proof

- Use a disposable model repository or a private lab fork with two commits: one reviewed pin and one default-branch change that modifies a non-sensitive processor/config/side-weight canary.
- Start vLLM with the reviewed `--revision` and, where applicable, `--code-revision`. Capture startup logs, Hugging Face cache paths, or controlled canary behavior that proves a nested artifact came from the unpinned/default revision.
- Validate one boundary at a time: dynamic module import, GGUF file path, side weights, image/audio processor, or same-repository subfolder.
- Do not point production inference workers at untrusted public model repos just to prove execution. Keep payloads inert, such as a harmless marker string or synthetic config value.

### Anyquery deletion proof

- Test only against a disposable Anyquery instance or an explicitly approved target. Create a synthetic directory outside the plugin-cache root but still owned by the Anyquery service account, for example a temporary `skillz-anyquery-canary` directory.
- Submit a benign query that calls `clear_plugin_cache()` with a traversal path from the plugin-cache root to the canary directory.
- Vulnerable evidence shows the canary directory was removed while the SQL function was intended to operate only under `$XDG_CACHE_HOME/anyquery/plugins/`.
- Do not target home directories, application data, logs, databases, SSH material, model caches, or any non-disposable path.

## Reporting heuristics

- Lead with the exact boundary: **revision pin not applied to all runtime artifacts** or **SQL plugin helper escapes cache root before recursive deletion**.
- Include preconditions: who controls the model reference, who can trigger service restart/model load, who holds the Anyquery bearer token, and what filesystem permissions the service account has.
- Prefer artifact-resolution evidence over broad RCE claims. For AI serving, a strong report shows the mismatch between reviewed/pinned artifacts and what actually loaded.
- Keep canaries synthetic and redact repository names or tokens if they belong to a customer environment.

## October 27 16:1xZ follow-up: the pin went the other way, request-body `mm_processor_kwargs.code_revision` selects EXECUTED processor code ([CVE-2026-114053 / GHSA-h3rc-6mm3-gc2m](https://github.com/advisories/GHSA-h3rc-6mm3-gc2m), high, vLLM 0.7.3-<0.31.0)

An untrusted multimodal request sets `mm_processor_kwargs.code_revision`; when the served model's HF processor uses dynamic `auto_map` code and the operator ran `--trust-remote-code`, the request value reaches `AutoProcessor.from_pretrained` and selects **which Python revision of the same model repo gets imported**. The operator's model/data `revision` stays pinned, the pin covers the weights, not the executed code path. Module import = arbitrary code execution in the API/renderer process (PoC is an import-time filesystem write, offline, no GPU/weights needed).

Operator rules extending this page's pin-decay set:

1. **Per-request revision fields are per-request CODE SELECTION.** The earlier legs were startup-time pin decay; this leg puts the revision knob in the *request body*. Audit: enumerate every per-request field name containing `revision`, `version`, `variant`, `code_`, or `config_` in any multimodal/generation schema and test whether it reaches a loader (`from_pretrained`, `import_module`, `Auto*` factories) alongside `trust_remote_code`-class flags.
2. **Fingerprint triad before testing:** (a) served model uses dynamic `auto_map` processor code (visible in the model repo's `preprocessor_config.json` `auto_map` field, readable without touching the server), (b) `--trust-remote-code` observable via startup banner/config endpoint or by the presence of custom-processor models in the served set, (c) multimodal endpoint accepts `mm_processor_kwargs`. All three remotely checkable.
3. **Same-host, different-revision probe:** a benign second revision of an owned canary repo (a revision whose `__init__` writes a marker file) proves code selection without loading hostile code. Never import untrusted third-party repos on shared workers.

## November 17 second follow-up: ModelScope SyncDreamer `target:` in syncdreamer.yaml is `instantiate_from_config()` code selection, no allowlist, no trust_remote_code check (CVE-2026-130839 / [GHSA-gp8m-xpr4-qj9w](https://github.com/advisories/GHSA-gp8m-xpr4-qj9w), high 7.8, 1.11.0 to <1.40.1)

The image-to-3D pipeline builds objects from the model's own `syncdreamer.yaml`: the `target` field names **any importable class** and its params are taken from the same config, so a model published to the hub with `target: os.system`-shaped content executes code **when a victim loads it**, with no allowlist and without even requiring `trust_remote_code`. This is the config-file mirror of the `code_revision` leg above: last time the request selected which revision of code to import; this time the model's config selects **which class at all**, and the trust decision was never made anywhere.

Operator rules:

- **Grep every `instantiate_from_config`/`_target_`/`class_path` pattern before trusting a config format.** The diffusers/accelerate `_target_` genealogy (Hydra-style config-driven instantiation) is a standing fingerprint across Python ML repos: `grep -rn "instantiate_from_config\|import_module(.*config\|class_path\|_target_" code/`. Each hit with an attacker-influenceable config (hub model, uploaded workflow, shared pipeline) is a candidate import-time RCE that `trust_remote_code` toggles do **not** cover, because the loader authors never routed it through the trust gate.
- **Hub model audit is a recon primitive.** For any ModelScope/HF repo: read the YAML/JSON configs (no code execution needed), enumerate `target`/`_target_`/`auto_map`/`code_` fields, and diff against the repo's declared module tree; a target naming anything outside the package namespace is the smoking gun. Proofs stay with an owned canary repo whose target class writes a marker file under a lab user.
- Same-page doctrine reaffirmed: model repositories are code repositories; the audit surface is every field that names a module or class, wherever the config originates.
