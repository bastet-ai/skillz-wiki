# CI, agent, stream, and file-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because CI scanners, agent hubs, SSE streams, and model-serving frontends turn metadata into filesystem reads, unbounded network reads, client-side events, or resource exhaustion. Those paths are easy to dismiss as tooling, but they often run with repository, token, or operator privileges.

## Advisories covered

- **ciguard symlink escape** — [GHSA-8cxw-cc62-q28v](https://github.com/advisories/GHSA-8cxw-cc62-q28v): pipeline discovery follows symlinks outside the scan root.
- **ciguard unbounded SCA response** — [GHSA-xw8c-rrvx-f7xq](https://github.com/advisories/GHSA-xw8c-rrvx-f7xq): HTTP client reads dependency-analysis responses without a size cap.
- **ciguard root container image** — [GHSA-jrm4-4pcf-4763](https://github.com/advisories/GHSA-jrm4-4pcf-4763): container image runs as root due to missing `USER` directive.
- **ciguard missing web hardening headers** — [GHSA-7ww3-xvf5-cxwm](https://github.com/advisories/GHSA-7ww3-xvf5-cxwm): web UI lacks defense-in-depth HTTP headers.
- **MCPHub manifest path traversal** — [GHSA-p3h2-2j4p-p83g](https://github.com/advisories/GHSA-p3h2-2j4p-p83g): malicious MCPB manifest name can traverse paths.
- **sse-channel event injection** — [GHSA-84hm-wfh8-c5pg](https://github.com/advisories/GHSA-84hm-wfh8-c5pg): unsanitized SSE event fields allow stream/event injection.
- **vLLM special-token remote DoS** — [GHSA-hpv8-x276-m59f](https://github.com/advisories/GHSA-hpv8-x276-m59f): special-token placeholders can trigger remote denial of service.

## Operator triage

1. Run CI/security scanners in read-only, low-privilege containers; mount repositories with no host secrets and verify path discovery never follows symlinks outside the intended root.
2. Cap HTTP response sizes and download times for SCA, metadata, model, and package-index clients; log truncation and fail closed on over-budget responses.
3. Review MCP/agent manifest installers for `../`, absolute paths, Unicode separators, symlinks, nested archives, and generated filenames derived from package metadata.
4. Fuzz SSE fields with embedded CR/LF, `event:`, `id:`, and `retry:` lines; verify each field is encoded as data and cannot mint extra events.
5. Rate-limit and budget model-serving token expansion, placeholder handling, prompt length, and concurrent requests.

## Durable controls

- Tooling containers should declare a non-root user, drop Linux capabilities, use read-only root filesystems, and keep workspace mounts scoped to the scan target.
- File discovery must resolve realpaths after every hop and reject symlinks/junctions that leave the canonical root.
- Stream protocols need field-level serialization helpers; never concatenate raw user-controlled lines into SSE, WebSocket, or log frames.
- Model-serving frontends need token, memory, and time budgets enforced before expensive placeholder or tokenizer expansion.
- Security tooling should be treated as production attack surface because it commonly has repository and credential reach.
