# GoFiber forwarded-IP and Artemis STOMP routing-type boundary checks

Source: hourly offensive-security scan, 2026-07-02. Primary entries: GitHub Advisory Database [GHSA-gcfq-8gqf-4876](https://github.com/advisories/GHSA-gcfq-8gqf-4876) / CVE-2026-45045, [GHSA-g5vh-55hw-rxm8](https://github.com/advisories/GHSA-g5vh-55hw-rxm8) / CVE-2026-44332, and [GHSA-rf99-f9j2-gv3f](https://github.com/advisories/GHSA-rf99-f9j2-gv3f) / CVE-2026-40914.

These advisories are durable for operators because they expose reusable trust-boundary failures: reverse-proxy helpers appending attacker-supplied client-IP headers instead of replacing them, Basic Auth middleware leaking valid usernames through default authorizer timing, and message brokers letting STOMP users with send or consume permissions augment an address routing type without the stronger address-creation permission. Keep validation to owned labs, synthetic identities, disposable queues, and harmless canary routes only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-gcfq-8gqf-4876](https://github.com/advisories/GHSA-gcfq-8gqf-4876) / CVE-2026-45045 | GoFiber `middleware/proxy.BalancerForward` | `X-Real-IP` was added with `Header.Add()` instead of replacing any client-supplied value | Test whether applications behind GoFiber trust the first forwarded-IP value for ACLs, rate limits, geofencing, or audit logic. |
| [GHSA-g5vh-55hw-rxm8](https://github.com/advisories/GHSA-g5vh-55hw-rxm8) / CVE-2026-44332 | GoFiber BasicAuth default authorizer | nonexistent usernames returned before password-hash verification, while valid usernames ran bcrypt or another verifier | Username-enumeration checks should include latency distributions, especially when Basic Auth protects admin or internal routes. |
| [GHSA-rf99-f9j2-gv3f](https://github.com/advisories/GHSA-rf99-f9j2-gv3f) / CVE-2026-40914 | Apache ActiveMQ Artemis / Apache Artemis STOMP protocol | send/consume permission could augment an address routing type without `createAddress` permission | Broker authorization reviews need protocol-specific checks that operation permissions cannot mutate address topology or delivery semantics. |

## Operator triage

1. **Inventory the trust consumer, not just the proxy.** The GoFiber issue matters when an upstream application, API gateway, or middleware reads `X-Real-IP` and gives it authority for access control, throttling, fraud logic, or logging.
2. **Test duplicate-header interpretation end to end.** Different stacks choose first value, last value, comma-join, or reject duplicates. Capture the exact behavior of the GoFiber hop and the upstream framework.
3. **Measure auth oracles statistically.** For the BasicAuth issue, compare many valid-username/wrong-password attempts against many invalid-username attempts under stable network conditions; do not treat a single slow request as proof.
4. **Model message-broker verbs as state changes.** In Artemis, a user who can send or consume should not be able to change which routing types an address supports. Check `anycast`/`multicast` behavior per protocol.
5. **Bound evidence.** Use fake usernames, test-only CIDR values, disposable addresses, and marker messages. Do not brute-force real users, spoof production allowlists, or consume live broker traffic.

## Replayable validation boundaries

### GoFiber `X-Real-IP` append vs replace check

- Preconditions: owned GoFiber lab or explicitly authorized customer test, `BalancerForward` in front of a controlled upstream echo or canary route, and no production IP allowlist being targeted.
- Send a baseline request without `X-Real-IP` and record every client-IP signal observed by the upstream: raw headers, framework-parsed IP, access-log value, rate-limit key, and any ACL decision.
- Send a request with a harmless spoofed header such as `X-Real-IP: 198.51.100.77` while connecting from a different test client address.
- Positive evidence: the upstream receives two `X-Real-IP` values and the application chooses the attacker-controlled first value for a security-relevant decision.
- Negative controls: patched GoFiber using replacement semantics, upstream duplicate-header rejection, trusted-proxy middleware that strips inbound client-IP headers before adding canonical values, and controls that use the socket peer rather than headers.
- Do not use internal or customer addresses as spoof markers unless the engagement explicitly authorizes that exact allowlist test.

### GoFiber BasicAuth username timing check

- Preconditions: owned GoFiber route using the default BasicAuth authorizer with hashed test credentials, one known valid test username, and one guaranteed invalid synthetic username.
- Collect a sample set for `valid-user:wrong-password` and `invalid-user:wrong-password` over the same network path. Record status, median, p95, and outliers.
- Positive evidence: valid-user failures consistently take the hash-verification path while invalid-user failures return near-immediately.
- Negative controls: a fixed build or custom authorizer that performs a dummy hash comparison for unknown users, plus jitter tests proving the difference is not network noise.
- Never enumerate production usernames or run high-volume password attempts against live systems.

### Artemis STOMP routing-type authorization check

- Preconditions: disposable Artemis broker, STOMP enabled, a test address with an intentionally limited routing-type configuration, and a test principal with only send or consume permission on that address.
- Confirm the test principal cannot explicitly create or modify the address through the normal management/API path.
- Using STOMP only, attempt to send to or consume from the address with a routing type not currently supported by that address, carrying a harmless marker message.
- Positive evidence: the operation succeeds and the address supports or behaves as if it supports the additional routing type despite the principal lacking `createAddress` permission.
- Negative controls: fixed Artemis version, a principal without send/consume permission, and the same operation against an address whose routing type is already authorized.
- Keep the broker empty except for marker messages; do not consume customer queues, alter production topics, or test with real credentials.

## Reporting notes

- Lead with the crossed boundary: **client-supplied forwarded-IP header to upstream trust decision**, **username existence to timing side channel**, or **STOMP send/consume permission to address-routing mutation**.
- Include affected version, topology, trust consumer, raw request or STOMP frame shape, positive/negative decision table, and synthetic marker values.
- Avoid claiming full access-control bypass unless the target actually uses the spoofed IP or routing-type mutation for a privileged decision in the tested deployment.
