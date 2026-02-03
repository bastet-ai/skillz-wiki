# 2026-02-02 — Clawdbot: multiple high-severity RCE paths (fixed in 2026.1.29)

## What happened
On 2026-02-02, multiple GitHub Security Advisories were published for **OpenClaw/Clawdbot** (notably affecting the **macOS menubar app** in Remote/SSH mode and the **Control UI** token handling).

## Impact
Depending on the vector, an attacker could achieve:

- **1‑click remote compromise of a gateway** via **token exfiltration** from a crafted `gatewayUrl` link opened in a browser (Control UI)
- **Local command execution** by injecting SSH client flags via a leading-dash target (e.g. `-oProxyCommand=...`)
- **Remote command execution on a configured SSH host** via shell/script construction issues involving **unescaped project path** content

## Affected / fixed
- Package: `clawdbot` (npm)
- **Fixed in:** `2026.1.29`

> Advisory notes indicate: CLI / web gateway / iOS / Android are not affected by the SSH-path injection issue; the affected components are the macOS menubar app (Remote/SSH mode) and the Control UI behavior.

## Durable guidance (defender playbook)
### 1) Patch first
- **Upgrade to `clawdbot@2026.1.29` or later** everywhere.
- If you distribute a desktop app, **force-update / auto-update**.

### 2) Until patched: reduce blast radius
- **Avoid Remote/SSH mode** where possible.
- Treat all **SSH targets** as untrusted input; do not accept targets from shared configs, tickets, or chat without verification.
- Treat all **gateway URLs** as untrusted input.

### 3) Control UI hardening (token theft → full control)
This class of issue is a reminder that “local-only” services are still vulnerable via **browser-initiated cross-origin connections**.

- Do not auto-connect to arbitrary gateway endpoints from URL parameters.
- Prefer an explicit **user confirmation** step for any new gateway URL.
- Restrict where the Control UI can be served from and who can reach it.
- Consider isolating the Control UI in a dedicated browser profile with no risky extensions.

### 4) SSH command construction: never interpolate
If your product constructs shell scripts/commands:

- Avoid `sh -c` when possible; use exec with argv arrays.
- If you must generate a script, **escape every interpolated field** (or better: remove interpolation entirely).
- Validate SSH host strings (e.g., **reject leading `-`** and other flag-like patterns).

## References
- GHSA-g8p2-7wf7-98mq — “1‑Click RCE via Authentication Token Exfiltration From gatewayUrl”
- GHSA-q284-4pvr-m585 — “OS Command Injection via Project Root Path in sshNodeCommand” + “SSH target flag injection”
- GHSA-mc68-q9jw-2h3v — “Docker execution command injection via PATH”

GitHub advisory feed: https://github.com/security-advisories.atom
