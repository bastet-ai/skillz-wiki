# 2026-02-04 — OpenClaw unauthenticated local RCE via WebSocket `config.apply` (GHSA-g55j-c2v4-pjcg)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** An **unauthenticated local client** could use the Gateway WebSocket API to write config via `config.apply` and set unsafe `cliPath` values. Later command discovery could invoke a shell, enabling **command injection** and **arbitrary code execution** as the gateway user.

## Why this matters
Even if this is “local only”, it turns any foothold on the host (another service compromise, a malicious user, a poisoned developer tool) into quick escalation to the gateway account and anything the gateway can access.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.1.20** or later.
- **Defense-in-depth (recommended even after patch):**
  - Require auth on the gateway API (`gateway.auth`) and rotate any shared secrets.
  - Bind the gateway API to **localhost** only when possible.
  - Avoid custom `cliPath` overrides unless necessary; treat them as privileged configuration.
  - Run the gateway under a **least-privilege** user with minimal filesystem and network access.

## Detection / hunting ideas
- Review gateway logs for unexpected `config.apply` calls.
- Audit recent config changes for suspicious `cliPath` values or unusual executable resolution.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-g55j-c2v4-pjcg>
