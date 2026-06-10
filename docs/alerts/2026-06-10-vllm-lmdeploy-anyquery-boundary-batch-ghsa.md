# vLLM and Anyquery boundary checks

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-3ww4-5jv9-j5gm](https://github.com/advisories/GHSA-3ww4-5jv9-j5gm) / CVE-2026-47155 for vLLM artifact pin decay and [GHSA-j9rx-rppg-6hh4](https://github.com/advisories/GHSA-j9rx-rppg-6hh4) / CVE-2026-47253 for Anyquery plugin-cache traversal.

This batch is durable because it turns advisory details into repeatable operator checks for AI inference artifact integrity and SQL-exposed filesystem deletion helpers. Use it for authorized assessments of model-serving platforms, AI/ML deployment pipelines, and self-hosted data-query services.

## What changed

- **vLLM artifact pin decay** — deployments that pass `--revision` or `--code-revision` can still resolve behavior-affecting artifacts from an unpinned/default revision. Reported boundaries include external `auto_map` dynamic module imports without `code_revision`, GGUF direct-file downloads without `revision`, BGE-M3 side weights with `revision=None`, Kimi image/audio processors, and same-repository subfolder weights/config that are not bound to the reviewed pin.
- **Anyquery plugin-cache traversal deletion** — the SQL scalar function `clear_plugin_cache(plugin)` joins the caller-controlled plugin name under the Anyquery cache root and calls `os.RemoveAll`. `..` segments can escape the intended plugin-cache directory when a bearer-token holder can submit SQL through `/v1/query` or another query path that exposes the function.

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
