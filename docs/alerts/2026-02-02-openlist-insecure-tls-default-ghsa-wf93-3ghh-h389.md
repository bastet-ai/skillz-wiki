# 2026-02-02 — OpenList ships with insecure TLS defaults (GHSA-wf93-3ghh-h389)

## Summary

A GitHub Security Advisory reports that **OpenList** disables **TLS certificate verification by default** for outgoing storage driver communications.

This enables **Man-in-the-Middle (MitM)** attacks that can lead to **decryption, theft, and manipulation** of data in transit.

- Advisory: https://github.com/advisories/GHSA-wf93-3ghh-h389
- Root cause (example): defaulting `TlsInsecureSkipVerify` to `true` (certificate verification skipped)

## What to do (durable guidance)

This is a recurring class of failure: **shipping insecure-by-default TLS settings**.

### If you operate affected software

1. **Inventory and confirm settings**
   - Find any configuration flags like:
     - `InsecureSkipVerify`
     - `tlsSkipVerify`
     - `verifyTls=false`
   - Assume that “it works in dev” often means “verification is disabled”.

2. **Turn verification on (and test correctly)**
   - Enable certificate verification for all outbound TLS connections.
   - Fix the root cause of failures (correct CA bundle / intermediate chain / SNI / hostname).

3. **Make exceptions explicit and scoped**
   - If you must allow unverified TLS temporarily:
     - make it **opt-in**, not default
     - scope it to a specific endpoint
     - add **hard expiration** (time-bomb) and loud logging/metrics

4. **Treat internal networks as hostile**
   - MitM is feasible via rogue Wi‑Fi, ARP spoofing, compromised routers/switches, or malicious proxies.
   - “Only internal traffic” is not a control.

### If you build software (how to avoid this class)

- **Secure defaults:** certificate verification ON by default.
- **Configuration validation:** fail fast if verification is disabled without an explicit acknowledgement.
- **No silent downgrade:** if TLS verification is off, emit a **startup warning** and surface a health check signal.
- **Prefer trust configuration over bypasses:** allow supplying a CA bundle / pinset rather than `skipVerify`.

## Related Wisdom

- [Agent + CI Hardening](../best-practices/agent-ci-hardening.md)
- [Documentation](../best-practices/documentation.md)
