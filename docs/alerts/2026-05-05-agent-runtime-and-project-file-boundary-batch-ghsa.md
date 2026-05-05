# Agent runtime and project-file boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because agent/workflow helpers keep letting remote project metadata become local execution or persistent filesystem mutation. Hubs, MCP tools, validators, and model/runtime package managers need the same final guards as CI systems.

## Advisories covered

- **@evomap/evolver validator sandbox** — [GHSA-jxh8-jh77-xh6g](https://github.com/advisories/GHSA-jxh8-jh77-xh6g): sandbox allowlist permits `npm`/`npx`, enabling RCE from Hub-delivered validation tasks via lifecycle scripts.
- **@evomap/evolver proxy `/asset/submit`** — [GHSA-7xp7-m392-h92c](https://github.com/advisories/GHSA-7xp7-m392-h92c): unbounded request bodies can cause persistent disk-exhaustion DoS.
- **@evomap/evolver fetch** — [GHSA-cfcj-hqpf-hccf](https://github.com/advisories/GHSA-cfcj-hqpf-hccf): default-branch `safeId` path traversal allows Hub-controlled project-file overwrite and potential RCE.
- **Ollama** — [GHSA-x99g-8v8j-25j2](https://github.com/advisories/GHSA-x99g-8v8j-25j2): path traversal in model/runtime file handling.
- **open-websearch MCP tool** — [GHSA-v228-72c7-fx8j](https://github.com/advisories/GHSA-v228-72c7-fx8j): bracketed IPv6 literals and hostname-check gaps bypass private/local SSRF protections.
- **AstrBot** — [GHSA-h3rr-9wqj-v3c6](https://github.com/advisories/GHSA-h3rr-9wqj-v3c6): incomplete filtering of special elements.

## Operator triage

1. Find agent runtimes that fetch projects, prompts, validators, models, or tools from hubs or user-controlled repositories.
2. Remove `npm`, `npx`, shell, package-manager, and interpreter launchers from validator allowlists unless the validator runs in a disposable container without host credentials.
3. Cap request bodies, model pulls, and asset uploads at the reverse proxy and application layers; alert on repeated 413/507 errors and abnormal disk growth.
4. Hunt for overwritten project files, unexpected generated scripts, modified package lifecycle hooks, and model files outside approved storage roots.
5. Review MCP web-fetch tools for IPv6, IPv4-mapped IPv6, bracketed literals, DNS rebinding, redirects, and link-local/private/reserved address handling.

## Durable controls

- Agent helpers need a final filesystem boundary: canonicalize, require containment under a task root, reject symlinks, and write atomically to newly created paths.
- Treat hub-delivered validators as untrusted code. Run them in no-network, no-secret sandboxes with read-only source mounts and clean working directories.
- SSRF defenses must resolve and classify every hop, including redirects, DNS changes, bracketed IPv6, IPv4-mapped forms, and non-routable/reserved ranges.
- Upload and proxy endpoints need hard byte, file-count, extraction, and disk-quota limits before data reaches durable storage.
- Filters for special elements or prompt/tool markup should be structural parsers, not substring deny lists.
