# 2026-02-03 — SiYuan arbitrary file write → RCE (GHSA-c4jr-5q7w-f6r9)

**What happened:** SiYuan had an arbitrary file write via `/api/file/copyFile`, which can lead to **remote code execution**.

**Why it matters:** Arbitrary file write vulnerabilities are frequently exploitable to RCE via:
- writing webshells / server-side templates
- overwriting startup scripts/config
- dropping plugins/extensions

## Durable guidance (defensive)

For defenders operating self-hosted apps:

1. **Patch/upgrade immediately** (arbitrary file write is high severity).
2. **Reduce blast radius**
   - run the service as an unprivileged user
   - containerize and mount application code as read-only
3. **Watch for IOCs**
   - unexpected file creation outside upload dirs
   - modified startup scripts, cron entries, or plugin directories

## References

- GitHub Advisory Database: <https://github.com/advisories/GHSA-c4jr-5q7w-f6r9>
