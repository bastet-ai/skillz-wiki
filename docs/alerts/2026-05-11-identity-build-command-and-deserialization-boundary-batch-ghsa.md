# Identity, build command, and deserialization-boundary batch

Source: GitHub Security Advisories REST fallback updated 2026-05-11.

This batch is durable because four different products failed at the same class of boundary: claims, identifiers, build metadata, and serialized objects were treated as authority instead of hostile input. Token exchange, profile ownership, CI branch names, and PHP object graphs all need explicit policy before they touch privileged actions.

## Advisories covered

- **Unity Catalog issuer validation bypass / user impersonation** — [GHSA-qqcj-rghw-829x](https://github.com/advisories/GHSA-qqcj-rghw-829x), CVE-2026-27478: Maven `io.unitycatalog:unitycatalog-server <=0.4.0` accepted JWT token-exchange input where the `iss` claim selected the OIDC/JWKS source dynamically. Attackers could host their own OIDC metadata/JWKS, sign a token for any known `sub` or `email`, and exchange it for an internal Unity Catalog access token. The advisory also notes missing `aud` validation. Fixed in `0.4.1`.
- **MantisBT global profile authorization bypass** — [GHSA-68w5-w573-q2r8](https://github.com/advisories/GHSA-68w5-w573-q2r8), CVE-2026-33052: Composer `mantisbt/mantisbt >=2.28.0,<2.28.2` allowed a low-privileged authenticated user with `add_profile_threshold` to create a global profile by tampering with `user_id`, bypassing `manage_global_profile_threshold`. Fixed in `2.28.2`.
- **WebdriverIO BrowserStack service command injection** — [GHSA-5c46-x3qw-q7j7](https://github.com/advisories/GHSA-5c46-x3qw-q7j7), CVE-2026-25244: npm `@wdio/browserstack-service <=9.23.2` interpolated git branch metadata into shell commands during BrowserStack test orchestration / smart selection. A malicious repository or branch name could execute commands on developer or CI hosts. Fixed in `9.24.0`.
- **torrentpier PHP serialize injection** — [GHSA-h29g-c9cx-c73q](https://github.com/advisories/GHSA-h29g-c9cx-c73q): Composer `torrentpier/torrentpier <=2.4.3` contained PHP object-deserialization injection paths that could enable code execution or arbitrary file access where attacker-controlled serialized data reaches vulnerable sinks. Fixed in `2.4.4`.

## Operator triage

1. Patch Unity Catalog servers to **0.4.1+** immediately. Treat exposed `/api/1.0/unity-control/auth/tokens` endpoints as high priority and review access-token issuance logs for unusual issuer URLs, unfamiliar OIDC discovery hosts, or token exchanges for privileged users.
2. For Unity Catalog, hard-code trusted issuer and JWKS metadata, require expected `aud`, `iss`, signature algorithm, and subject mapping policy, and invalidate tokens issued during any suspected exploit window.
3. Patch MantisBT to **2.28.2+** and search profile/audit data for global profiles created by users who lack `manage_global_profile_threshold`; remove unauthorized profiles and review any workflow that trusts global profile metadata.
4. Patch `@wdio/browserstack-service` to **9.24.0+**. Before running untrusted branches or forked PRs, disable BrowserStack smart-selection/test-orchestration features or isolate them in CI jobs with no secrets, read-only checkout tokens, and no deploy credentials.
5. Patch torrentpier to **2.4.4+**. Inventory endpoints, cookies, cache/state files, and queued payloads that may deserialize PHP objects; rotate credentials and inspect web/PHP logs if attacker-controlled serialized strings reached those paths.

## Durable controls

- Token exchange must bind `iss`, `aud`, JWKS URI, algorithm, and subject mapping to a preconfigured trust relationship; never let an incoming token choose its own trust root.
- Authorization checks must evaluate immutable server-side identity and permission state. Client-controlled IDs such as `user_id` can select records, but cannot select the actor or privilege scope.
- Build and test automation must treat repository metadata — branch names, tags, commit messages, remote names, and paths — as attacker-controlled. Pass metadata as argv arrays, not shell strings, and run fork/PR jobs without secrets.
- PHP `unserialize()` and other object-graph deserializers are code-adjacent. Prefer JSON/schema data formats; if legacy object state is unavoidable, require authenticated integrity, strict type allowlists, and a separate least-privileged worker.
- Incident response should tie these findings together: if the boundary crosses from data into identity, shell, or object construction, assume compromise until logs and affected versions prove otherwise.

## Related Wisdom

- [Agent tool command injection](../best-practices/agent-tool-command-injection.md)
- [JWT token minting and refresh hardening](../best-practices/jwt-token-minting-refresh-hardening.md)
- [Python pickle: never deserialize untrusted data](../best-practices/python-pickle-untrusted-deserialization.md)
