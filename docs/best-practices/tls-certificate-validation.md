# TLS certificate validation (don’t ship `skipVerify`)

## Summary

Disabling TLS certificate validation (e.g., `InsecureSkipVerify=true`, `verify=False`, `--insecure`, `curl -k`) converts “TLS” into **unencrypted trust-by-assumption**.

It is a recurring root cause behind:

- **MitM** (traffic interception/modification)
- credential/session theft
- data corruption in transit
- “internal network” compromise chains (rogue Wi‑Fi, ARP spoofing, malicious proxies)

## Durable guidance

### 1) Make verification **ON by default**

- Default behavior must validate:
  - certificate chain
  - hostname / SNI
  - validity period / revocation stance (your org policy)
- Treat “works when skipVerify is enabled” as a **bug in trust configuration**, not an acceptable state.

### 2) Fix trust properly (don’t bypass it)

When verification fails, the right fixes are usually:

- correct **CA bundle** (including private/internal PKI)
- correct **intermediate chain** served by the server
- correct **hostname** (certificate SAN matches the DNS name you use)
- correct **SNI** (client sets the expected server name)

Prefer configurable trust:

- `--ca-file` / `caBundlePath`
- `trustStore` / `certPool`
- (optionally) **certificate pinning** for high-value internal services

### 3) If you must allow insecure mode, make it expensive

If business reality forces a temporary bypass:

- **opt-in only** (never default)
- **scoped** to a specific endpoint/host
- **time-bombed** (hard expiration date)
- **loudly logged** (startup warning + metric + healthcheck signal)
- blocked in production via policy/guardrails if possible

### 4) Detect and prevent regressions

- Code scanning for:
  - `InsecureSkipVerify`, `verify=False`, `RejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
- CI tests that fail if insecure flags are set in prod configs
- Runtime assertion: refuse to start if insecure TLS is enabled without an explicit “I understand” acknowledgement.

## Common anti-patterns

- “It’s only internal traffic.” (internal networks are compromise terrain)
- “We’ll enable it later.” (later rarely happens)
- “We validate in staging only.” (attackers target prod)
- “We block RCE so it’s fine.” (MitM enables tampering, not just sniffing)

## Related Wisdom

- [OpenList insecure TLS defaults (GHSA-wf93-3ghh-h389)](../alerts/2026-02-02-openlist-insecure-tls-default-ghsa-wf93-3ghh-h389.md)
- [Agent + CI Hardening](agent-ci-hardening.md)
