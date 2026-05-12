# OpenClaw runtime and channel boundary refresh

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because it shows recurring automation-platform failures: media fetches, loopback identity, filesystem bridges, channel callbacks, rotated secrets, exec environments, and browser automation must all re-check authority at the exact boundary where the effect happens.

## Advisories covered

- **Zalo outbound photo URL SSRF validation** — [GHSA-2hh7-c75g-qj2r](https://github.com/advisories/GHSA-2hh7-c75g-qj2r): outbound photo URLs now pass through the SSRF guard instead of trusting channel-supplied media references.
- **MCP loopback owner context from bearer tokens** — [GHSA-r6xh-pqhr-v4xh](https://github.com/advisories/GHSA-r6xh-pqhr-v4xh): loopback identity must come from server-issued bearer tokens, not ambient connection assumptions.
- **QQBot direct media upload SSRF validation** — [GHSA-c4qg-j8jg-42q5](https://github.com/advisories/GHSA-c4qg-j8jg-42q5): direct upload paths need the same URL validation as ordinary fetch paths.
- **Workspace dotenv runtime-control override** — [GHSA-hxvm-xjvf-93f3](https://github.com/advisories/GHSA-hxvm-xjvf-93f3): project-local `.env` files could override high-risk runtime-control variables.
- **OpenShell filesystem bridge read/write pinning** — [GHSA-5h3g-6xhh-rg6p](https://github.com/advisories/GHSA-5h3g-6xhh-rg6p), [GHSA-wppj-c6mr-83jj](https://github.com/advisories/GHSA-wppj-c6mr-83jj): reads and writes must verify the opened/resolved file remains under the sandbox mount root.
- **Matrix room command authorization** — [GHSA-2gvc-4f3c-2855](https://github.com/advisories/GHSA-2gvc-4f3c-2855): room control commands must not trust stale DM pairing-store entries.
- **Feishu webhook/card validation fail-closed** — [GHSA-xh72-v6v9-mwhc](https://github.com/advisories/GHSA-xh72-v6v9-mwhc): callbacks and card actions need strict signature and sender validation before parsing privileged intent.
- **Gateway bearer auth after SecretRef rotation** — [GHSA-xmxx-7p24-h892](https://github.com/advisories/GHSA-xmxx-7p24-h892): HTTP endpoints must re-resolve auth material after secrets rotate.
- **Exec interpreter startup variable denylist** — [GHSA-vfp4-8x56-j7c5](https://github.com/advisories/GHSA-vfp4-8x56-j7c5): process sandboxes need deny-by-default treatment for language startup variables.
- **Browser/CDP navigation and second-hop SSRF** — [GHSA-xq94-r468-qwgj](https://github.com/advisories/GHSA-xq94-r468-qwgj), [GHSA-536q-mj95-h29h](https://github.com/advisories/GHSA-536q-mj95-h29h), [GHSA-f7fh-qg34-x2xh](https://github.com/advisories/GHSA-f7fh-qg34-x2xh): browser actions and `/json/version` WebSocket discovery must guard DNS rebinding, navigation side effects, and untrusted second-hop targets.

## Operator triage

1. Upgrade OpenClaw deployments that expose channel media fetches, browser automation, MCP loopback, OpenShell, Matrix/Feishu controls, or Gateway HTTP endpoints.
2. Review logs for blocked media URL fetches, unexpected browser target pivots, control-command attempts from rooms/chats that were not explicitly authorized, and local `.env` overrides of runtime flags.
3. Rotate Gateway/channel/MCP tokens if vulnerable endpoints were reachable by untrusted users or untrusted networks before patching.
4. Re-run SSRF, path containment, channel auth, and secret-rotation tests after upgrade; do not rely on a single startup-time config read.

## Durable controls

- Every external URL sink must use one shared SSRF policy, including direct upload paths and channel-specific media helpers.
- Filesystem bridges must check containment after resolution/open, not only before path join.
- Channel callbacks should fail closed before body parsing, card action dispatch, or command execution.
- Runtime sandboxes should construct an allowlisted environment instead of trying to enumerate dangerous variables.
- Browser automation should validate the final connection target and all navigation-producing actions, not just the initial requested URL.
