# 2026-02-02 — fog-kubevirt: MitM risk from disabled certificate validation (GHSA-m3hq-3qj8-c5fm)

## Summary

A GitHub Security Advisory reports that **fog-kubevirt** allowed a remote attacker to perform a **Man-in-the-Middle (MitM)** attack because **TLS certificate validation was disabled**.

- Advisory: https://github.com/advisories/GHSA-m3hq-3qj8-c5fm
- CWE: CWE-295 (Improper Certificate Validation)

## What to do (durable guidance)

This is a classic “TLS verification off” failure mode.

1. **Ensure certificate verification is enabled** for all outbound TLS connections.
2. **Fix trust configuration** (CA bundle, intermediates, hostname/SNI) rather than bypassing verification.
3. If you must temporarily bypass, make it **opt-in, scoped, time-bombed, and loudly logged**.

## Related Wisdom

- [TLS certificate validation (don’t ship `skipVerify`)](../best-practices/tls-certificate-validation.md)
- [OpenList insecure TLS defaults (GHSA-wf93-3ghh-h389)](../alerts/2026-02-02-openlist-insecure-tls-default-ghsa-wf93-3ghh-h389.md)
