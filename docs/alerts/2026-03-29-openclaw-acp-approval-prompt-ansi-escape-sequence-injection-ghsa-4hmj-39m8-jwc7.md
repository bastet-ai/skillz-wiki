# 2026-03-29 — OpenClaw ACP approval prompt ANSI escape sequence injection (GHSA-4hmj-39m8-jwc7)

**Product:** **OpenClaw** (npm package: `openclaw`)

**Impact (per advisory):** Untrusted tool titles could carry ANSI control sequences into approval prompts and logs, letting attacker-controlled text spoof what the human sees.

## Why this matters
Approval UIs and permission logs are trust boundaries. If attacker-controlled labels can inject terminal control codes, they can hide text, change colors, or make a malicious prompt look safe.

## Recommended actions
- **Patch/upgrade:** update to **openclaw 2026.3.28** or later.
- **Strip ANSI/control sequences** from all untrusted labels before rendering.
- **Treat logs as hostile render targets**; prefer plain-text output.
- **Test approval surfaces** with escape-sequence payloads.

## Detection / hunting ideas
- Grep approval and logging paths for raw untrusted titles or labels.
- Add tests with `\x1b[` sequences to confirm they are neutralized.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-4hmj-39m8-jwc7>
