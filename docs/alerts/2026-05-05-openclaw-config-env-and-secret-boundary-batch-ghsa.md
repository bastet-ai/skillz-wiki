# OpenClaw config, env, and secret-boundary batch

Source: GitHub Security Advisories, published/updated 2026-05-05.

This batch is durable because it reinforces a high-value operator lesson: AI/runtime assistants need final, mechanical guards around configuration mutation, environment-key resolution, and secret rotation. Model intent is not a security boundary.

## Advisories covered

- **OpenClaw gateway config mutation guard** — [GHSA-cwj3-vqpp-pmxr](https://github.com/advisories/GHSA-cwj3-vqpp-pmxr): unsafe model-driven config writes were possible through insufficient mutation guarding.
- **OpenClaw env-key resolution** — [GHSA-r39h-4c2p-3jxp](https://github.com/advisories/GHSA-r39h-4c2p-3jxp): attacker-controlled `setup-api.js` loaded from current working directory could lead to arbitrary code execution during environment-key resolution.
- **OpenClaw Webhooks SecretRef rotation** — [GHSA-q8ff-7ffm-m3r9](https://github.com/advisories/GHSA-q8ff-7ffm-m3r9): route secrets remained valid after rotation/reload.

## Operator triage

1. Upgrade OpenClaw to a release containing fixes for these advisories before allowing model-driven config workflows or untrusted workspace interaction.
2. Review gateway config history for unexpected provider, command, browser, webhook, MCP, ACP, or filesystem-scope changes.
3. Search workspaces for unexpected `setup-api.js` files, especially in directories used for config, provider setup, or environment-key workflows.
4. Rotate webhook SecretRefs, then verify old secrets fail immediately without process restart, cache delay, or dual-secret grace windows unless deliberately configured.
5. Audit logs for config apply/mutation calls initiated from model/tool contexts rather than explicit operator-approved paths.

## Durable controls

- Config writes require schema-level allowlists, provenance checks, and final non-model policy enforcement immediately before persistence.
- Environment-key helpers must import code only from trusted packaged locations, never from the current working directory or workspace-controlled paths.
- Secret rotation must invalidate old verifier material at the same boundary that accepts requests; stale route caches are authentication bypasses.
- Sensitive config changes should produce immutable audit entries with actor, source channel, diff summary, approval context, and reload result.
- Treat workspace files as attacker-controlled when they can affect runtime setup, provider discovery, plugin loading, or command routing.
