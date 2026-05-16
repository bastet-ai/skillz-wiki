# Open WebUI model, render, cache, and execution-boundary batch

Sources: GitHub Security Advisories updates on 2026-05-15.

This batch is durable because model platforms often hide control-plane power behind friendly collaboration features. Model descriptions, shared model details, Jupyter/code toggles, Ollama compatibility routes, model chaining, imports, Redis key namespaces, and pending-user UI all need to be treated as boundary surfaces, not presentation details.

## Advisories covered

- **Open WebUI: Jupyter code execution works despite `ENABLE_CODE_EXECUTION=false` — feature gate bypassed** — [GHSA-482j-2pq6-q5w4](https://github.com/advisories/GHSA-482j-2pq6-q5w4) / CVE-2026-45672 (high).
- **Open WebUI: Sharing models for others to use (read permission) also exposes model details (system prompt leakage)** — [GHSA-h2cw-7qw9-56xr](https://github.com/advisories/GHSA-h2cw-7qw9-56xr) / CVE-2026-45387 (medium).
- **Open WebUI's Ollama Model Access Control Bypass via /api/generate, /api/embed, /api/embeddings, and /api/show** — [GHSA-rcvp-6fgw-c7fh](https://github.com/advisories/GHSA-rcvp-6fgw-c7fh) / CVE-2026-44563 (medium).
- **Open WebUI's Model Import Overwrites Any Model Without Ownership Check** — [GHSA-mqq6-cqcx-38vg](https://github.com/advisories/GHSA-mqq6-cqcx-38vg) / CVE-2026-44562 (medium).
- **Open WebUI's Base Model Routing Bypasses Access Control via Model Chaining** — [GHSA-9vvh-qmjx-p4q8](https://github.com/advisories/GHSA-9vvh-qmjx-p4q8) / CVE-2026-44555 (high).
- **Open WebUI: Redis Cache Keys tool_servers and terminal_servers Missing Instance Prefix Enable Cross-Instance Cache Poisoning** — [GHSA-3x8w-4f7p-xxc2](https://github.com/advisories/GHSA-3x8w-4f7p-xxc2) / CVE-2026-44552 (high).
- **open-webui Vulnerable to Stored XSS via Model Description** — [GHSA-gf5m-wcrh-7928](https://github.com/advisories/GHSA-gf5m-wcrh-7928) / CVE-2026-44721 (high).
- **Open WebUI has Stored XSS in Pending User Overlay via Incorrect DOMPurify Application Order** — [GHSA-fq3v-xjjx-95rc](https://github.com/advisories/GHSA-fq3v-xjjx-95rc) / CVE-2026-44568 (medium).

## Operator triage

1. Check whether Open WebUI deployments expose Jupyter/code execution, Ollama compatibility endpoints, model sharing/import, pending-user overlays, Redis-backed terminal/tool servers, or model chaining/base routing.
2. Verify `ENABLE_CODE_EXECUTION=false` blocks every code path that can spawn kernels or execute notebooks; do not rely on UI feature hiding.
3. Probe model import/share/chaining flows with non-owner users and confirm system prompts, base model access, Ollama endpoints, and imported model overwrites cannot cross ownership boundaries.
4. If Redis is shared across instances, inspect terminal/tool server cache keys and isolate or rotate any instances that may have accepted poisoned cross-instance entries.

## Durable controls

- Feature gates must be enforced in backend execution paths and worker launch code, not just frontend routing or configuration display.
- Model metadata can contain secrets and instructions. Sharing read access to a model should not expose system prompts, provider parameters, or owner-only routing details by default.
- Compatibility endpoints such as Ollama and responses/completions APIs must call the same authorization layer as first-party routes.
- Cache keys for multi-instance deployments need unpredictable deployment/tenant prefixes and authenticated producers; shared Redis is part of the trust boundary.
- Render every model/user-supplied description and admin overlay with context-aware encoding after sanitization, and regression-test sanitizer order.
