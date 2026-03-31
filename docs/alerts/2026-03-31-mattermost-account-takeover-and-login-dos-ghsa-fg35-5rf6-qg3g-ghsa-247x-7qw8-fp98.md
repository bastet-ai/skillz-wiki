# Mattermost account takeover substring matching flaw and login rate-limit DoS

**Signal:** Two GitHub Security Advisories landed in the same update window:

- **GHSA-fg35-5rf6-qg3g** — Mattermost allows attackers to take over arbitrary user accounts via overly permissive substring matching flaw
- **GHSA-247x-7qw8-fp98** — Mattermost doesn't rate limit login requests, allowing DoS

## Why this matters
These are different bug classes, but they point at the same defensive lesson:

- **Identity logic must be exact, not fuzzy**
- **Authentication endpoints must be rate-limited and monitored by default**
- A single auth surface can become both a takeover path and an availability target

## Durable guidance
### 1) Treat account matching as a security boundary
If your product maps external identities, aliases, email prefixes, usernames, or display names into an account:

- Require **exact canonical matching** after normalization
- Do not use substring, prefix, regex-wildcard, or partial-match logic for account selection
- Keep a clear separation between:
  - user-provided display text
  - canonical identity keys
  - lookup indexes used for authorization decisions
- Add tests for ambiguous inputs such as:
  - `ann` vs `joann`
  - `admin` vs `superadmin`
  - case-folded duplicates
  - Unicode lookalikes and normalization edge cases

### 2) Put rate limits on all login paths
Every login entry point should have:

- per-IP throttles
- per-account throttles
- per-credential / per-identifier throttles where appropriate
- burst and sustained-rate controls
- clear metrics for lockouts, retries, and error spikes

Do not rely on upstream WAFs alone. Enforce controls in the app or auth layer so they survive topology changes.

### 3) Alert on auth anomalies
Watch for:

- high-frequency login attempts from a small set of sources
- distributed attempts against one account
- repeated failures followed by success
- unexpected account-linking or identity-resolution events
- spikes in expensive auth work such as password hashing, OTP validation, or external directory lookups

### 4) Test the edge cases explicitly
Security tests should include:

- exact-match vs partial-match identity resolution
- Unicode normalization and case-folding collisions
- extremely long usernames and email prefixes
- repeated login attempts until throttling triggers
- retry behavior across success, failure, and lockout states

## References
- GitHub advisories feed: <https://github.com/security-advisories.atom>
- GHSA-fg35-5rf6-qg3g
- GHSA-247x-7qw8-fp98
