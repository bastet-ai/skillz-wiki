# 2026-02-05 — Sliver website subsystem path traversal → arbitrary file read (authenticated) (GHSA-2286-hxv5-cmp2)

GitHub published an advisory for **Sliver** (Bishop Fox) describing a **path traversal / arbitrary file read** issue in the *website content* subsystem.

- Advisory: <https://github.com/advisories/GHSA-2286-hxv5-cmp2>

## Why this matters (durable guidance)

This is a recurring failure mode in many systems that manage “content”:

- you accept a *path* from a user/operator (sometimes “trusted”, sometimes not)
- you store it
- later you read from disk using something like `Join(baseDir, userPath)`

If `userPath` can contain `../` (or Windows equivalents), `Join()` alone does **not** prevent escaping the intended directory.

Even when the bug is *“only authenticated”*, it can still be a major problem when:

- you have multiple operators / roles (insider risk, compromised operator account)
- the server host has secrets readable by the Sliver server user
- this becomes a stepping stone to lateral movement

## Impact (per advisory)

- **Arbitrary file read** on the Sliver server host as the Sliver server OS user.
- Potential exposure of:
  - operator configs
  - TLS keys / tokens
  - credentials and other secrets present on disk

## Triage

1. Determine whether you use / enable Sliver’s **website content** features.
2. Treat this as **host secret exposure** risk:
   - identify what secrets are on the Sliver server filesystem
   - confirm least-privilege for the Sliver server OS account
3. Check for suspicious operator activity (new websites/content paths, unusual reads).

## Mitigation

- **Patch/upgrade Sliver** to a version that fixes GHSA-2286-hxv5-cmp2.
- Reduce blast radius:
  - run the Sliver server under a dedicated, least-privileged OS user
  - keep secrets out of that account’s readable paths
  - segment the Sliver server host from sensitive internal resources
- Defensive engineering pattern (applies broadly):
  - canonicalize (`Clean`/`Resolve`) the candidate path
  - enforce “must stay under base directory” (deny if it escapes)
  - reject absolute paths and path components like `..`

See also: [Archive extraction: prevent path traversal + symlink escapes](../best-practices/archive-extraction-symlink-traversal.md)

## References

- <https://github.com/advisories/GHSA-2286-hxv5-cmp2>
