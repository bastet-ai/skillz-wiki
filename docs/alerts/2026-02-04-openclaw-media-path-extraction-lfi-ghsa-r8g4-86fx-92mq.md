# 2026-02-04 — OpenClaw local file inclusion via MEDIA: path extraction (GHSA-r8g4-86fx-92mq)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** A validation flaw around `MEDIA:` handling allows an agent to reference arbitrary local paths (absolute paths, `~`, `../` traversal). If a system renders or transmits `MEDIA:/path/to/file`, this can enable **arbitrary file read** and **data exfiltration** of secrets accessible to the agent process.

## Why this matters
This is a classic “tooling exfiltration” risk: the model/agent can be tricked into outputting a `MEDIA:` reference that causes the host to attach and send a sensitive file (SSH keys, cloud credentials, `.env`, config files).

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.1.30** or later.
- **Defense-in-depth (recommended even after patch):**
  - Enforce an allowlist of media directories (e.g., `/tmp/clawdbot-media/*`).
  - Reject `..`, `~`, and absolute paths unless they are inside the allowlisted root.
  - Run the agent with a least-privilege account; avoid giving it readable access to secrets.
  - Consider separate service accounts/containers per channel/task to compartmentalize.

## Detection / hunting ideas
- Search logs/transcripts for `MEDIA:/` patterns or references to sensitive filenames (`id_rsa`, `credentials`, `.env`).
- Audit what filesystem paths are readable by the agent runtime user.

## References
- Advisory: <https://github.com/openclaw/openclaw/security/advisories/GHSA-r8g4-86fx-92mq>
- GitHub advisory entry: <https://github.com/advisories/GHSA-r8g4-86fx-92mq>
