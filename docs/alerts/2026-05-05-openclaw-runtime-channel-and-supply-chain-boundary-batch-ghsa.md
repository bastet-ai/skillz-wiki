# OpenClaw runtime, channel, and supply-chain boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-06.

This batch is durable because the advisories cluster around the same operator lesson: assistant runtimes need final, non-model-enforced boundaries at every trust transition. Workspace files, channel payloads, paired devices, package indexes, browser redirects, and plugin-auth routes must not inherit privilege merely because they are inside an operator workflow.

## Advisories covered

### Environment and supply-chain routing

- **Base64 pre-allocation size checks** — [GHSA-ccx3-fw7q-rr2r](https://github.com/advisories/GHSA-ccx3-fw7q-rr2r): multiple code paths decoded large base64 payloads before enforcing allocation limits.
- **ClawHub package integrity** — [GHSA-3vvq-q2qc-7rmp](https://github.com/advisories/GHSA-3vvq-q2qc-7rmp): package downloads were not enforced with integrity verification.
- **Workspace `.env` plugin trust-root override** — [GHSA-qcj9-wwgw-6gm8](https://github.com/advisories/GHSA-qcj9-wwgw-6gm8): workspace-controlled environment could override bundled plugin trust roots.
- **CLI backend env injection incomplete fix** — [GHSA-vfw7-6rhc-6xxg](https://github.com/advisories/GHSA-vfw7-6rhc-6xxg): workspace config could still inject backend environment variables.
- **Compiler binary substitution through env overrides** — [GHSA-g8xp-qx39-9jq9](https://github.com/advisories/GHSA-g8xp-qx39-9jq9): host env policy gaps allowed untrusted model-controlled compiler substitutions.
- **Git plumbing env denylist gap** — [GHSA-cm8v-2vh9-cxf3](https://github.com/advisories/GHSA-cm8v-2vh9-cxf3): `GIT_DIR` and related variables were missing from exec sanitization.
- **Python package-index redirection** — [GHSA-7ggg-pvrf-458v](https://github.com/advisories/GHSA-7ggg-pvrf-458v): `PIP_INDEX_URL` and `UV_INDEX_URL` bypassed host exec env sanitization.
- **Package-manager env redirection** — [GHSA-j7p2-qcwm-94v4](https://github.com/advisories/GHSA-j7p2-qcwm-94v4): host env sanitization allowed supply-chain redirection via package-manager variables.
- **Plugin install scan fail-open** — [GHSA-cwq8-6f96-g3q4](https://github.com/advisories/GHSA-cwq8-6f96-g3q4): security scan failure did not block plugin installation.

### Pairing, authorization, and operator scopes

- **Pair approval scope confusion** — [GHSA-67mf-f936-ppxf](https://github.com/advisories/GHSA-67mf-f936-ppxf): `node.pair.approve` was placed in `operator.write` instead of `operator.pairing`.
- **Concurrent shared-secret rate-limit bypass** — [GHSA-25wv-8phj-8p7r](https://github.com/advisories/GHSA-25wv-8phj-8p7r): async auth attempts could bypass the intended shared-secret budget.
- **Cross-channel allowlist writes** — [GHSA-vc32-h5mq-453v](https://github.com/advisories/GHSA-vc32-h5mq-453v): `/allowlist` omitted owner-only enforcement across channels.
- **Role-upgrade pairing bypass** — [GHSA-whf9-3hcx-gq54](https://github.com/advisories/GHSA-whf9-3hcx-gq54): `device.token.rotate` could mint tokens for unapproved roles.
- **Strict inline-eval approval fallback** — [GHSA-q2gc-xjqw-qp89](https://github.com/advisories/GHSA-q2gc-xjqw-qp89): approval-timeout fallback bypassed explicit approval for gateway and node exec hosts.
- **Shared-secret timing leak** — [GHSA-jj6q-rrrf-h66h](https://github.com/advisories/GHSA-jj6q-rrrf-h66h): comparison call sites leaked length information through timing.
- **Node event gateway RCE** — [GHSA-gjm7-hw8f-73rq](https://github.com/advisories/GHSA-gjm7-hw8f-73rq): paired nodes could escalate to gateway RCE through unrestricted `node.event` agent dispatch.
- **Plugin-auth route scope leak** — [GHSA-mhgq-xpfq-6r66](https://github.com/advisories/GHSA-mhgq-xpfq-6r66): unauthenticated plugin-auth HTTP routes received operator runtime scopes.

### Browser, channel, and media pre-auth boundaries

- **Playwright redirect SSRF** — [GHSA-w8g9-x8gx-crmm](https://github.com/advisories/GHSA-w8g9-x8gx-crmm): strict browser SSRF handling left private targets reachable after redirects.
- **Persistent browser profile mutation** — [GHSA-cmfr-9m2r-xwhq](https://github.com/advisories/GHSA-cmfr-9m2r-xwhq): `node.invoke(browser.proxy)` bypassed persistent profile-mutation guards.
- **Voice-call frame parsing before validation** — [GHSA-2w79-r9g8-wmcr](https://github.com/advisories/GHSA-2w79-r9g8-wmcr): large WebSocket frames were parsed before start validation.
- **Teams webhook body parse before JWT validation** — [GHSA-p464-m8x6-vhv8](https://github.com/advisories/GHSA-p464-m8x6-vhv8): unauthenticated webhook bodies could cause resource exhaustion.
- **Feishu sender allowlist bypass** — [GHSA-877v-w3f5-3pcq](https://github.com/advisories/GHSA-877v-w3f5-3pcq): thread history and quoted messages bypassed sender allowlists.
- **Zalo replay-cache scope bypass** — [GHSA-hhq4-97c2-p447](https://github.com/advisories/GHSA-hhq4-97c2-p447): replay cache keys were scoped too broadly across targets.
- **Discord audio preflight before member authorization** — [GHSA-hhff-fj5f-qg48](https://github.com/advisories/GHSA-hhff-fj5f-qg48): transcription preflight ran before authorization.
- **Nostr private-key redaction bypass** — [GHSA-jjw7-3vjf-fg5j](https://github.com/advisories/GHSA-jjw7-3vjf-fg5j): `config.get` could expose plaintext Nostr signing keys.

## Operator triage

1. Upgrade OpenClaw before allowing untrusted workspaces, plugins, browser sessions, package installs, paired nodes, or channel webhooks to interact with operator scopes.
2. Audit recent command, exec, build, plugin, and package-install logs for unexpected `GIT_*`, package-index, compiler, trust-root, or backend environment variables.
3. Treat workspace `.env`, config, and package-manager inputs as hostile. Rebuild any plugin or binary installed while these advisories may have been reachable.
4. Review paired-node and channel logs for unapproved role upgrades, pairing approvals, allowlist edits, plugin-auth calls, browser proxy invocations, and `node.event` dispatches.
5. Rotate high-value secrets exposed through runtime config or channel integrations, especially Nostr private keys and shared secrets used on webhook/device paths.
6. For webhook/audio/voice paths, verify authentication, size caps, and replay checks happen before body parsing, transcription, or frame buffering.

## Durable controls

- Keep a deny-by-default environment policy for host exec. Allow variables by exact purpose, not broad prefixes, and include package managers, compilers, Git plumbing, Python/Node/Ruby build tooling, and plugin trust roots.
- Package/plugin downloads need pinned provenance: signatures, hashes, lockfiles, verified source roots, and fail-closed security scans.
- Authorization must be checked at the action boundary: pairing approval, role minting, allowlist writes, plugin auth, browser profile mutation, and node event dispatch each need distinct scopes.
- Resource limits must apply before decoding or parsing attacker-controlled input. Base64, WebSocket frames, webhook bodies, and media preflight paths are all pre-auth attack surfaces.
- Browser SSRF defenses must re-evaluate every redirect, proxy hop, DNS resolution, and existing-session profile mutation.
- Channel integrations should bind replay caches and allowlists to channel/account/target identity, not only message IDs or quoted-message metadata.
- Secret comparisons require constant-time checks over normalized, fixed-length representations and shared rate-limit state across concurrent auth attempts.
