# Agent context and broker-secret boundary checks

Source: hourly offensive-security scan, 2026-06-30. Primary entries: GitHub Advisory Database [GHSA-wm96-9gfh-vvgq](https://github.com/advisories/GHSA-wm96-9gfh-vvgq), [GHSA-pgp4-xr4j-h5cg](https://github.com/advisories/GHSA-pgp4-xr4j-h5cg), [GHSA-238w-f66p-w349](https://github.com/advisories/GHSA-238w-f66p-w349), and [GHSA-v9gv-xp36-jgj8](https://github.com/advisories/GHSA-v9gv-xp36-jgj8). Reviewed but not promoted: [GHSA-v5pm-xwqc-g5wc](https://github.com/advisories/GHSA-v5pm-xwqc-g5wc), because the published impact is OpenAPI parser process termination only.

These items are durable for operators because they expose reusable boundaries: agent runtime context and skill metadata crossing into prompts or tool decisions, code-execution helpers crossing sandbox/environment-variable boundaries, and message-broker plugin state crossing into logs with reversible credential obfuscation. Keep validation to disposable agents, fake environment markers, inert skill names, and synthetic broker URIs; never collect real prompts, credentials, chat transcripts, AMQP credentials, or production node logs.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-wm96-9gfh-vvgq](https://github.com/advisories/GHSA-wm96-9gfh-vvgq) | `hermes-agent` `execute_code` environment-variable handling | code-execution tooling can expose or mishandle host environment state across the intended sandbox boundary | Treat agent code runners as sandbox plus secret-propagation surfaces; validate with fake env markers and isolated profiles before trusting remote or untrusted task content. |
| [GHSA-pgp4-xr4j-h5cg](https://github.com/advisories/GHSA-pgp4-xr4j-h5cg) | `hermes-agent` prompt/context scanning | context content can influence downstream prompt-building decisions | Test whether files, retrieved pages, docs, or memory entries can inject instructions that alter tool scope, privilege, or evidence handling. |
| [GHSA-238w-f66p-w349](https://github.com/advisories/GHSA-238w-f66p-w349) | `hermes-agent` skills guard / multi-word threat-pattern handling | skill metadata or guard patterns can cross from classification into execution policy | Agent skill marketplaces and local skill bundles need inert canary skills that prove guards cannot be bypassed or poisoned by attacker-controlled wording. |
| [GHSA-v9gv-xp36-jgj8](https://github.com/advisories/GHSA-v9gv-xp36-jgj8) | RabbitMQ Shovel and Federation plugins | plugin worker/link state used predictable URI obfuscation, so exception logs could contain deobfuscatable upstream credentials | Message-broker assessments should include synthetic Shovel/Federation URI log-canaries and verify whether operators can recover secrets from logs after plugin errors. |

## Operator triage

1. **Separate the agent surfaces.** Identify context sources, skill manifests, guard/classifier rules, code-execution tools, and environment variables before testing payloads. A prompt injection finding is stronger when it reaches a policy or tool boundary, not just model text.
2. **Use fake markers for secrets.** Set `SKILLZ_CANARY_TOKEN=not-a-secret-<case-id>` in a disposable runner and confirm whether code execution, logs, memory, or context summaries reveal it. Do not test with real API keys, shell history, SSH agent sockets, cloud metadata, or production environment variables.
3. **Treat skill bundles as supply-chain inputs.** A malicious skill name, description, trigger phrase, or threat-pattern-like text should be tested the same way as repository-controlled CI config: inert payload, isolated profile, no real credentials, and a fixed-version negative control.
4. **Broker logs are credential stores when obfuscation is reversible.** Shovel/Federation URIs often embed usernames, passwords, vhosts, and upstream hosts. If exceptions print obfuscated state, prove recovery only with throwaway AMQP URIs.
5. **Skip parser-crash-only items unless they unlock a non-availability path.** The Microsoft.OpenAPI advisory is useful for availability testing but does not currently add a durable offensive workflow for this wiki.

## Replayable validation boundaries

### Agent context, skill guard, and code-runner harness

- Preconditions: explicit authorization, a disposable `hermes-agent` or equivalent agent profile, no real memories/skills/secrets, and a temporary workspace that can be deleted after testing.
- Seed one fake environment variable and one harmless outside-workspace canary file. The canary values should be unique and non-sensitive.
- Create test inputs for each ingress path the target agent supports: local docs, fetched web content, memory text, skill name/description, and task prompt. Use inert strings such as `CANARY_DO_NOT_EXECUTE_<id>` rather than destructive commands.
- Exercise the normal code-execution/tool path and record whether environment values, outside-workspace paths, or skill/guard decisions cross the intended boundary.
- For prompt/context scanning, prove a concrete effect: a tool call allowed or denied incorrectly, a policy decision flipped, or a protected instruction surfaced as trusted context. Do not claim impact from model-visible text alone.
- For skill guards, include multi-word, encoded, case-folded, punctuation-split, and benign-near-match variants; evidence should show the final guard decision and the skill/tool actually selected.
- Negative controls: patched package versions, per-tool env allowlists, no inherited host env by default, canonical workspace checks, explicit skill trust prompts, and guard decisions that bind to normalized tokens rather than raw prompt fragments.

### RabbitMQ Shovel/Federation URI log-canary harness

- Preconditions: lab RabbitMQ node, disposable Shovel/Federation plugin configuration, throwaway upstream URI, and log access approved by the owner.
- Configure a synthetic upstream URI with a marker username/password such as `amqp://canary_user:canary_pass_<id>@broker.invalid/vhost`.
- Trigger only a benign connection or configuration error that exercises worker/link state logging. Do not point at production upstream brokers or customer vhosts.
- Capture the log line containing obfuscated URI state, then verify offline whether the published vulnerable versions allow the marker to be recovered. Keep the recovered value redacted except for the canary suffix.
- Negative controls: patched RabbitMQ versions (`3.10.2`, `3.9.18`, `3.8.32` or later for the affected branches), cluster-wide secret-backed obfuscation, and no credential-bearing URI material in exception logs.

## Reporting notes

- Lead with the exact crossed boundary: **agent code runner to host environment**, **untrusted context to prompt/tool policy**, **skill metadata to guard bypass**, or **broker plugin state to deobfuscatable log secret**.
- Include package/product versions, profile/plugin configuration, input source, canary value label, observed decision or log location, and fixed-version negative control.
- Keep artifacts synthetic: fake environment variables, disposable profiles, inert skills, controlled prompt snippets, lab RabbitMQ nodes, and throwaway AMQP URIs.
