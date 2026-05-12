# Parser, render, and consensus-boundary batch

Source: GitHub Security Advisories updated 2026-05-12.

This batch is durable because parser and rendering edges are still being treated as harmless convenience paths even when they can fetch network resources, disclose or corrupt API output, or split distributed consensus.

## Advisories covered

- **Biopython `Bio.Entrez` XXE** — [GHSA-x3vf-39hj-gxr4](https://github.com/advisories/GHSA-x3vf-39hj-gxr4): XML parsing with doctypes can expose local files or trigger entity expansion when external entities are enabled.
- **wlc `print_html` unescaped API data** — [GHSA-gx2m-mcc2-r4p3](https://github.com/advisories/GHSA-gx2m-mcc2-r4p3): CLI or reporting helpers that output HTML still need contextual escaping for API-controlled fields.
- **Zebra JSON-RPC resource and consensus bugs** — [GHSA-29x4-r6jv-ff4w](https://github.com/advisories/GHSA-29x4-r6jv-ff4w), [GHSA-8m29-fpq5-89jj](https://github.com/advisories/GHSA-8m29-fpq5-89jj), [GHSA-452v-w3gx-72wg](https://github.com/advisories/GHSA-452v-w3gx-72wg): interrupted authenticated JSON-RPC requests, transparent sighash hash-type handling, and identity-point transaction verification can produce DoS or consensus divergence/panic conditions.

## Operator triage

1. Patch XML/data science dependencies that parse remote or user-supplied data, and disable external entity resolution globally where possible.
2. Review reports, CLI `--html` modes, dashboards, and generated documentation for unescaped fields from API responses or service metadata.
3. For blockchain/consensus nodes, prioritize coordinated patch rollout, check fork/panic telemetry, and avoid mixing vulnerable and fixed validator/miner fleets longer than necessary.
4. Add regression corpora for doctypes, nested entities, malformed points, interrupted HTTP/RPC requests, and rendering payloads that include tags, attributes, and scripts.

## Durable controls

- XML parsers should default to no external entities, no network fetches, bounded expansion, and explicit schema/doctype allowlists only when required.
- Rendering helpers need the same output-encoding discipline as web apps; “local” generated HTML is still executable content.
- Consensus-critical code needs differential tests across implementations and versions for every parser, hash, and signature edge case.
- Authenticated resource exhaustion is still exploitable: rate limits, cancellation-safe cleanup, and per-request budgets must apply after auth succeeds.
