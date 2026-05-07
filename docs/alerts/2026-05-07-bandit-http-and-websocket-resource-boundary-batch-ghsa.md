# Bandit HTTP and WebSocket resource-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-07** Bandit batch where HTTP parser decisions and WebSocket accounting could be turned into routing confusion, request smuggling, or unauthenticated memory exhaustion.

## Advisories covered

- **HTTP/2 frame-size limit bypass through late buffer checks** — [GHSA-q6v9-r226-v65f](https://github.com/advisories/GHSA-q6v9-r226-v65f)
- **Trusting client-supplied URI scheme on plaintext connections** — [GHSA-375f-4r2h-f99j](https://github.com/advisories/GHSA-375f-4r2h-f99j)
- **CL.CL request smuggling via duplicate `Content-Length` headers** — [GHSA-c67r-gc9j-2qf7](https://github.com/advisories/GHSA-c67r-gc9j-2qf7)
- **Unbounded WebSocket continuation-frame buffering** — [GHSA-pf94-94m9-536p](https://github.com/advisories/GHSA-pf94-94m9-536p)
- **Unbounded WebSocket inflate causing BEAM OOM** — [GHSA-frh3-6pv6-rc8j](https://github.com/advisories/GHSA-frh3-6pv6-rc8j)

## Why this is durable

Protocol libraries are security boundaries when they sit in front of auth, routers, reverse proxies, and application workers. Size checks that happen after buffering, scheme values copied from clients, and ambiguous `Content-Length` handling all create disagreements between layers that attackers can exploit.

## Immediate triage

1. Patch Bandit wherever it accepts internet, partner, webhook, agent, or tenant-controlled traffic.
2. Put duplicate `Content-Length`, conflicting transfer-encoding, HTTP/2 frame-limit, and WebSocket continuation/inflate regression cases into edge tests.
3. Enforce maximum compressed and decompressed WebSocket message sizes before buffering entire payloads.
4. Derive request scheme from the trusted listener/TLS termination context, not from plaintext client-controlled request targets.
5. Add proxy-pair tests for Bandit behind load balancers or ingress controllers to catch parser differentials.

## Durable controls

- Normalize each request once at the edge and pass a canonical request object to auth, routing, logging, and backend forwarding.
- Reject ambiguous framing early, before allocation and before any application dispatch.
- Track protocol memory budgets per connection, per request, and per tenant; fail closed when any budget is exceeded.
- Keep request-smuggling probes in continuous integration for every HTTP stack upgrade.
