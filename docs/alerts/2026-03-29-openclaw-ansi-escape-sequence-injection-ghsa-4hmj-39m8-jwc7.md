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

## Consolidation note
<!-- consolidation-note: wiki-redundancy-2026-05-22 -->

This is the canonical page for this topic. During the 2026-05-22 redundancy pass, overlapping pages were reduced to compatibility pointers:

- `alerts/2026-03-29-openclaw-acp-approval-prompt-ansi-escape-sequence-injection-ghsa-4hmj-39m8-jwc7.md`

## October 1 follow-up: remote monitoring telemetry drives the operator's terminal (collectl colmux, folded)

- **collectl <4.3.20.2 `colmux` terminal escape injection** (CVE-2026-103431, [GHSA-ggwj-h7wp-pg4f](https://github.com/advisories/GHSA-ggwj-h7wp-pg4f), high): colmux multiplexes data from remote collectl instances into the operator's terminal without sanitizing ANSI/VT100 escape sequences — a **local user on any monitored host** injects escape sequences into the terminal of whoever runs colmux, via a crafted process name (`argv[0]`). Same invariant as this page, new transport: the hostile string doesn't come from an agent tool title, it comes from *monitoring telemetry rendered in a management console*, and the attacker needs only an unprivileged foothold on a monitored box. The pivot vector is process names — attacker-controlled in almost every environment (`bash -c $'\e]0;payload\a'`, setproctitle, argv[0] exec tricks).
- Sweep rule extension: every display surface that renders remote-supplied strings in a terminal (multiplexes, log viewers, `ps`-style tables, dashboard TUIs, CI live-output renderers) gets the escape-canary test with the *remote-host* threat model: place a canary OSC/CSI sequence in a process name on a lab host the tool monitors and observe the console host's terminal state (title, colors, cursor). OSC 52 clipboard-write and OSC hyperlink sequences are the high-value canaries (clipboard poisoning / misleading link text against the operator). Treat "the data comes from a monitored system" as untrusted input, not as telemetry.
