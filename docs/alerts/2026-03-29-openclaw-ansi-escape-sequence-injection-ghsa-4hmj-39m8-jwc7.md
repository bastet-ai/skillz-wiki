# 2026-03-29 — OpenClaw ACP approval prompt ANSI escape sequence injection (GHSA-4hmj-39m8-jwc7)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** ACP tool titles could carry ANSI control sequences into approval prompts and permission logs, allowing untrusted metadata to spoof terminal output.

## Why this matters
Approval prompts and audit logs are part of the trust boundary. If untrusted tool metadata can inject ANSI control sequences, an attacker can hide text, alter colors, reposition the cursor, or make a malicious prompt look like a benign one.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.28** or later.
- **Sanitize untrusted strings before display:** strip ANSI CSI/control sequences from tool names, titles, and any other user-controlled labels.
- **Treat logs as hostile rendering surfaces:** render escape-aware or plain-text only in approval UIs, terminals, and recorders.
- **Audit other prompt surfaces:** ensure similar protections exist anywhere external metadata is surfaced to a human decision point.

## Detection / hunting ideas
- Grep approval/logging paths for raw tool titles or labels passed directly to terminal output.
- Review whether any UI or log sink preserves ANSI sequences from external inputs.
- Test with escaped titles like `\x1b[31m` to confirm they are neutralized.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-4hmj-39m8-jwc7>
