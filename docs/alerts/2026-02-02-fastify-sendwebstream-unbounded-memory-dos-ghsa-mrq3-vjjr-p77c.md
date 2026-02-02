# 2026-02-02 — Fastify DoS via unbounded memory allocation in sendWebStream (GHSA-mrq3-vjjr-p77c)

## Summary

A GitHub Security Advisory reports that **Fastify** can be driven into **excessive/unbounded memory allocation** when using `sendWebStream`, potentially causing **Denial of Service (DoS)**.

This fits a recurring failure mode in modern web stacks: **streaming APIs that still buffer unexpectedly** (or buffer under attacker control).

- Advisory: https://github.com/advisories/GHSA-mrq3-vjjr-p77c

## What to do (durable guidance)

### If you operate affected software

1. **Upgrade Fastify**
   - Apply the fixed versions from the advisory.

2. **Enforce resource limits around streaming responses**
   - Put a hard cap on:
     - per-request response size
     - time-to-first-byte and total duration
     - concurrent connections
   - Ensure your reverse proxy (nginx/envoy/caddy/cloud LB) also has sensible limits.

3. **Monitor for memory pressure as a security signal**
   - Alert on:
     - memory growth correlated to request rate
     - spikes in long-lived connections
     - increased 5xx due to OOM / restarts

### If you build services (how to avoid this class)

- Assume any “streaming” interface can still become a **buffering sink** under real-world conditions.
- Treat **connection count** as an attacker-controlled input; require:
  - rate limiting
  - per-IP concurrency controls
  - timeouts
- Add stress tests that simulate slow clients and large responses.

## Related Wisdom

- [Debug mode is not a feature](../best-practices/debug-mode-is-not-a-feature.md)
