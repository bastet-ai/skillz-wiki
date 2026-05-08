# Stream, proxy, WebSocket, and resource-boundary batch

**Signal:** The **2026-05-08 21:15 UTC** advisory scan added boundary issues in event streams, telemetry exporters, cluster webhooks, agent WebSocket UIs, application SSRF, and long-poll body parsing.

## Advisory cluster

- **eventsource-encoder SSE event injection** — [GHSA-m9g3-3g99-mhpx](https://github.com/advisories/GHSA-m9g3-3g99-mhpx): `eventsource-encoder <=1.0.1` let attacker-controlled `event` or `id` fields inject extra Server-Sent Events; patch to `1.0.2+`.
- **OpenTelemetry.Exporter.Instana proxy TLS validation bypass** — [GHSA-wfr5-454p-mjc2](https://github.com/advisories/GHSA-wfr5-454p-mjc2): `OpenTelemetry.Exporter.Instana <=1.0.7` bypassed certificate validation when a proxy was configured; patch to `1.1.0+`.
- **Volcano admission webhook unbounded body DoS** — [GHSA-8wxp-xxp2-rcgx](https://github.com/advisories/GHSA-8wxp-xxp2-rcgx): `volcano.sh/volcano` webhook server accepted unbounded HTTP bodies; patch to `1.12.4+`, `1.13.3+`, or `1.14.2+`.
- **Cline Kanban Server CSWSH** — [GHSA-5c57-rqjx-35g2](https://github.com/advisories/GHSA-5c57-rqjx-35g2): `cline <=2.13.0` exposed a critical Cross-Origin WebSocket Hijacking path in the Kanban server; no patched version was listed at scan time.
- **monetr Lunch Flow SSRF** — [GHSA-29v9-frvh-c426](https://github.com/advisories/GHSA-29v9-frvh-c426): `github.com/monetr/monetr <1.12.5` allowed server-side fetches during Lunch Flow link creation/refresh; patch to `1.12.5+`.
- **Phoenix long-poll NDJSON allocation DoS** — [GHSA-628h-q48j-jr6q](https://github.com/advisories/GHSA-628h-q48j-jr6q): `phoenix >=1.7.0,<1.7.22` and `>=1.8.0,<1.8.6` could allocate excessive memory while splitting long-poll NDJSON request bodies.

## Why this matters

These are all “framing is authority” failures: an event field becomes another event, a proxy path disables TLS identity, a browser-origin WebSocket inherits a user session, or a body parser accepts attacker-chosen allocation size.

## Triage

1. Patch eventsource-encoder, Instana exporter, Volcano, monetr, and Phoenix where present; isolate or disable Cline Kanban Server exposure until an upstream fix is available.
2. For WebSocket UIs and agent dashboards, require strict `Origin` checks, unpredictable connection tokens, and same-site/session-binding checks before accepting frames.
3. Audit telemetry exporters configured with HTTP proxies; verify they still perform certificate-chain and hostname validation against the intended collector.
4. Add body-size limits before JSON, NDJSON, webhook, and admission-review parsing.
5. Hunt for unexpected SSE event names/IDs, Cline Kanban cross-origin traffic, Volcano webhook OOM/restart events, and monetr link-refresh fetches to loopback, metadata, RFC1918, or link-local addresses.

## Durable controls

- Encode SSE `event`, `id`, and `data` as separate fields with CR/LF rejection; never concatenate raw user strings into stream frames.
- Treat proxy support as an alternate transport, not an alternate trust model: TLS verification must survive proxy mode.
- Put explicit max bytes/read deadlines in front of every webhook and long-poll body parser.
- Gate WebSockets on `Origin`, per-session nonce, authentication, and authorization before any state-changing message.
- Centralize SSRF egress policy for link preview, refresh, webhook, and connector features.
