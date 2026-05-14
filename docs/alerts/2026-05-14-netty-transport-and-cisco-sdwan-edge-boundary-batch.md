# Netty transport and Cisco SD-WAN edge-boundary batch

Sources: GitHub Security Advisories and CISA KEV updates on 2026-05-14.

This batch links two different failure modes with the same operational lesson: edge-facing transport and control-plane components need explicit abuse budgets. A half-closed TCP connection can become an event-loop availability issue, and an SD-WAN controller authentication bypass is already a CISA KEV "move now" signal.

## Advisories covered

- **Netty epoll native transport denial of service** — [GHSA-rwm7-x88c-3g2p](https://github.com/advisories/GHSA-rwm7-x88c-3g2p): `io.netty:netty-transport-native-epoll >= 4.2.0.Final, < 4.2.13.Final` could be forced into denial of service by a TCP connection reset while the connection is half-closed. Fixed in `4.2.13.Final`.
- **Cisco Catalyst SD-WAN Controller authentication bypass** — [CVE-2026-20182](https://nvd.nist.gov/vuln/detail/CVE-2026-20182): CISA added this to KEV on 2026-05-14. Cisco Catalyst SD-WAN Controller and Manager can allow unauthenticated remote attackers to obtain administrative privileges. CISA due date: 2026-05-17; follow [ED 26-03 mitigation instructions](https://www.cisa.gov/news-events/directives/ed-26-03-mitigate-vulnerabilities-cisco-sd-wan-systems), [hunt and hardening guidance](https://www.cisa.gov/news-events/directives/supplemental-direction-ed-26-03-hunt-and-hardening-guidance-cisco-sd-wan-systems), and Cisco advisory guidance.

## Operator triage

1. Inventory Java services using Netty `4.2.x` with Linux native epoll transport, especially public HTTP/gRPC/proxy endpoints and high-fan-in internal brokers.
2. Upgrade `io.netty:netty-transport-native-epoll` to `4.2.13.Final` or later; if patching is delayed, force non-epoll transport only as a temporary availability workaround and test latency/back-pressure behavior.
3. Monitor Netty event-loop crashes, channel exceptions, spikes in half-closed connections, and abnormal TCP RST rates from the same source networks.
4. Treat every internet-reachable Cisco SD-WAN Controller/Manager as emergency priority: restrict management exposure, apply Cisco/CISA mitigations, and discontinue exposed use where mitigations are unavailable.
5. Hunt Cisco SD-WAN logs for unexpected admin sessions, account creation, configuration exports/imports, token/API activity, device-template changes, policy pushes, and unusual source IPs before rotating credentials.
6. After Cisco containment, rotate administrator credentials, API tokens, SSO/OIDC secrets, device bootstrap material, and any credentials reachable from controller backups or configuration exports.

## Durable controls

- Transport stacks need adversarial TCP-state tests in CI and pre-production: half-close, RST, slow-drain, and reconnect storms should not kill event loops.
- Native acceleration paths are part of the trusted runtime. Track them as separately patchable dependencies, not as invisible performance details.
- SD-WAN controllers are identity and routing control planes. Keep them off the public internet, enforce admin MFA and source allowlists, and alert on configuration or policy changes as security events.
- KEV additions should trigger a dated mitigation clock, owner assignment, and compromise-assessment checklist, not just a patch ticket.
