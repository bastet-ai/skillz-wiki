# OpenClaw webchat local-file read and wildcard command-owner authorization issues (GHSA-gfg9-5357-hv4c / GHSA-c28g-vh7m-fm7v)

**Signal:** GitHub Security Advisories published **2026-04-29**. OpenClaw fixed two medium-severity boundary issues affecting webchat media embedding and owner-enforced channel commands.

## What it is
Two OpenClaw advisories landed after the prior runtime trust-boundary bundle:

- `GHSA-gfg9-5357-hv4c`: webchat audio embedding could read host-local audio-like files without applying the local media root containment check. A malicious tool output or prompt-injected `ReplyPayload.mediaUrl` could turn an agent response into a bounded local file disclosure path. Affected `openclaw <= 2026.4.14`; fixed in `2026.4.15` and later.
- `GHSA-c28g-vh7m-fm7v`: owner-enforced commands could treat wildcard channel `allowFrom: ["*"]` as command-owner authorization when `commands.ownerAllowFrom` was not explicitly set. Affected `openclaw <= 2026.4.20`; fixed in `2026.4.21`.

References:

- <https://github.com/advisories/GHSA-gfg9-5357-hv4c>
- <https://github.com/advisories/GHSA-c28g-vh7m-fm7v>

## Triage
1. Identify OpenClaw deployments older than `2026.4.21`; prioritize deployments exposing webchat or accepting inbound traffic from wildcard channel senders.
2. Review channel configs with `commands.enforceOwnerForCommands: true`, `allowFrom: ["*"]`, and no explicit `commands.ownerAllowFrom`.
3. Check webchat transcripts and media responses for unexpected embedded audio sourced from local absolute paths or `file:` URLs.
4. Confirm whether agents/tools can emit `ReplyPayload.mediaUrl` from untrusted content or remote tool results.

## Mitigation
- Upgrade OpenClaw to `2026.4.21` or later.
- Require concrete owner identities for owner-enforced commands; do not inherit wildcard inbound sender policy into command ownership.
- Apply local-root containment checks consistently to every media embedding and serving path, including audio-specific helpers.
- Treat model/tool-produced media URLs as untrusted input and normalize them before any file read.

## Detection ideas
- Search logs for owner-enforced slash commands from senders that are not explicit owners.
- Review `/send`, `/config`, `/debug`, and other sensitive command invocations around channels that allowed wildcard inbound senders.
- Look for webchat media responses containing base64 audio where the source URL was an absolute local path or `file:` scheme.
- Alert on failed local media containment checks after upgrade; they may indicate prompt injection or malicious tool output attempts.

## Durable lesson
Agent outputs cross trust boundaries too. Media helpers and command gates must re-derive authority from explicit, local policy—not from broad inbound accept rules or model-provided paths.
