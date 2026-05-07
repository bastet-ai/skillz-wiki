# Client token, build-context, and webhook identity boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-07** batch where trusted context was inferred too broadly: Cinny leaked Matrix access tokens through service-worker handling of untrusted media URLs, BentoML followed symlinks out of build contexts, and OpenClaw Zalo webhook replay dedupe keys were insufficiently scoped across chat/sender dimensions.

## Advisories covered

- **Cinny Matrix access-token disclosure via emoji pack avatar URL** — [GHSA-j944-w549-3453](https://github.com/advisories/GHSA-j944-w549-3453) / [CVE-2026-42553](https://www.cve.org/CVERecord?id=CVE-2026-42553): before `4.10.3`, attacker-controlled emote-pack avatar metadata could cause the client/service worker to send the victim's Matrix access token to an attacker-controlled server when the emoji or sticker picker loaded.
- **BentoML build-context symlink traversal** — [GHSA-mcfx-4vc6-qgxv](https://github.com/advisories/GHSA-mcfx-4vc6-qgxv) / [CVE-2026-40610](https://www.cve.org/CVERecord?id=CVE-2026-40610): before `1.4.39`, `bentoml build` followed attacker-controlled symlinks inside the build context and copied target file contents into the generated Bento artifact.
- **OpenClaw Zalo replay dedupe key scope collision** — [GHSA-rxmx-g7hr-8mx4](https://github.com/advisories/GHSA-rxmx-g7hr-8mx4) / [CVE-2026-41354](https://www.cve.org/CVERecord?id=CVE-2026-41354): OpenClaw before `2026.4.2` could suppress legitimate webhook events across chats or senders because replay dedupe keys were not strongly scoped. [GHSA-6477-wvjj-47v6](https://github.com/advisories/GHSA-6477-wvjj-47v6) is a withdrawn duplicate.

## Why this is durable

These are confused-context bugs. A client treats remote media metadata as if it belonged to the same authenticated origin, a build tool treats symlinks as if they were ordinary project files, and a webhook processor treats replay identity as if one dimension were enough. Durable defense requires binding credentials, filesystem reads, and event dedupe to the exact origin/root/principal tuple they are meant to protect.

## Immediate triage

1. Patch Cinny to `4.10.3` or later and review rooms where untrusted users can create emote packs or stickers.
2. Treat Matrix access tokens from affected clients as exposed if users opened emoji/sticker pickers in rooms containing attacker-controlled packs; revoke sessions and review account activity.
3. Patch BentoML to `1.4.39` or later. Rebuild artifacts from trusted worktrees if they were produced from untrusted repositories or user-submitted model projects.
4. Inspect existing Bento artifacts for packaged secrets or host files that should never be inside model bundles.
5. Patch OpenClaw to `2026.4.2` or later and confirm webhook replay/dedupe keys include channel, chat, sender, platform message ID, and time-bucket dimensions as appropriate.

## Hunt prompts

- Service-worker or media fetch requests carrying Matrix access tokens to domains outside the expected homeserver/media proxy allowlist.
- Matrix sessions created, used, or synced from unfamiliar IPs after malicious emote/sticker interaction.
- Bento artifacts containing `/etc`, home-directory, SSH, cloud credential, `.env`, kubeconfig, or CI workspace paths.
- `bentoml build` logs from untrusted repos with symlinks, generated artifacts larger than expected, or files outside the project manifest.
- Zalo webhook logs with duplicate suppression across different chats/senders or missing event sequences after replay-key collisions.

## Durable controls

- Do not attach bearer tokens to arbitrary media URLs; route media through trusted proxy paths and enforce origin allowlists in service workers.
- Resolve symlinks during packaging and prove every final path remains under the build root; fail closed on absolute links, parent traversal, and special files.
- Generate build artifacts from clean, minimal contexts rather than full developer checkouts.
- Scope replay and idempotency keys to all security-relevant identity dimensions, not just a message ID or timestamp.
- Monitor “safety” systems such as dedupe, cache, and service-worker code as security boundaries because failures often look like missing messages or invisible data leaks.
