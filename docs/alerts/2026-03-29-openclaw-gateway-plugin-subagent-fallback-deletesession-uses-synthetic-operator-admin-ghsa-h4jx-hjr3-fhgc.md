# 2026-03-29 — OpenClaw gateway plugin subagent fallback `deleteSession` uses synthetic `operator.admin` (GHSA-h4jx-hjr3-fhgc)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** A fallback path in the gateway plugin could invoke `deleteSession` using a synthetic `operator.admin` identity instead of the real caller context.

## Why this matters
Fallbacks are dangerous when they change identity. If an error path fabricates an admin principal, the system can perform destructive actions that the real caller was never authorized to make.

## Recommended actions
- **Patch/upgrade** to the fixed OpenClaw release.
- **Never synthesize privileged identities** in fallback code.
- **Carry the verified principal through all destructive actions**.
- **Add tests** that ensure fallback paths fail closed.

## Detection / hunting ideas
- Audit all fallback handlers for fake admin context or default-privileged principals.
- Search for any path that can delete sessions without the caller’s real authorization context.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-h4jx-hjr3-fhgc>
