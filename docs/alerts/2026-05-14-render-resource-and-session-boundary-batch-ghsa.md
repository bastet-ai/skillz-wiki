# Render, resource, and session-boundary batch (GHSA)

Source: GitHub Security Advisories updated 2026-05-14.

This batch spans documentation renderers, telemetry propagation, federated chat, fitness-app sessions, encrypted archive metadata, and project scaffolding CLIs. The durable theme is that “supporting” surfaces — table-of-contents generation, baggage headers, trainer impersonation helpers, small encrypted files, and setup prompts — still carry real security boundaries.

## Advisories covered

- **Mistune TOC anchor injection XSS** — [GHSA-6269-cqxg-mhhv](https://github.com/advisories/GHSA-6269-cqxg-mhhv), CVE-2026-44898: `mistune == 3.2.0` inserted TOC `id` and text values into links without escaping. Fixed in `3.2.1`.
- **Mistune image directive CSS injection** — [GHSA-ccfx-mfmx-2fx9](https://github.com/advisories/GHSA-ccfx-mfmx-2fx9), CVE-2026-44899: prefix-only numeric validation allowed arbitrary CSS after leading digits in image directive width/height. Fixed in `3.2.1`.
- **OpenTelemetry Java baggage unbounded allocation** — [GHSA-rcgg-9c38-7xpx](https://github.com/advisories/GHSA-rcgg-9c38-7xpx), CVE-2026-45292: `opentelemetry-api` and trace propagators `<= 1.61.0` parsed oversized baggage without W3C size/entry limits and could fan out resource pressure downstream. Fixed in `1.62.0`.
- **Synapse local CPU starvation DoS** — [GHSA-8q93-326v-3m7g](https://github.com/advisories/GHSA-8q93-326v-3m7g), CVE-2026-45078: local authenticated users could starve other Synapse requests. Fixed in `matrix-synapse 1.152.1`.
- **Synapse federated pagination DoS** — [GHSA-6qf2-7x63-mm6v](https://github.com/advisories/GHSA-6qf2-7x63-mm6v), CVE-2026-45076: malicious federated events could prevent clients from receiving full history. Fixed in `1.152.1`.
- **wger trainer-login session chaining privilege escalation** — [GHSA-9qpr-vc49-hqg2](https://github.com/advisories/GHSA-9qpr-vc49-hqg2), CVE-2026-43978: trainer impersonation state could be chained into manager accounts. Affected `wger <= 2.5`; no patched version was listed at scan time.
- **wger template routine IDOR** — [GHSA-cj9g-27ph-4cgv](https://github.com/advisories/GHSA-cj9g-27ph-4cgv), CVE-2026-43977: authenticated users could read private workout logs/stats through public template routine actions. Affected `wger <= 2.5`; no patched version was listed at scan time.
- **pyzipper small-file encryption metadata leak** — [GHSA-crqm-m339-7m2p](https://github.com/advisories/GHSA-crqm-m339-7m2p), CVE-2026-44722: AE-2 was not automatically selected, leaving plaintext CRC32 metadata that aids brute force of small/low-entropy files. Fixed in `0.4.0`.
- **ApostropheCMS CLI command injection** — [GHSA-hcwq-x9fw-8cfq](https://github.com/advisories/GHSA-hcwq-x9fw-8cfq), CVE-2026-42853: `@apostrophecms/cli <= 3.6.0` embedded password-prompt input into a shell command during `apos create`. No patched version was listed at scan time.
- **OpenCms CMIS reflected/stored XSS surface** — [GHSA-8gpv-c454-3hfc](https://github.com/advisories/GHSA-8gpv-c454-3hfc), CVE-2023-42343: `org.opencms:opencms-core < 16.0` was vulnerable via `cmis-online/type`. Fixed in `16.0`.

## Operator triage

1. Patch Mistune, OpenTelemetry Java, Synapse, pyzipper, and OpenCms where present; isolate or restrict wger and ApostropheCMS CLI usage until fixed releases are available.
2. For public documentation renderers, regenerate user-authored pages after patching and search stored Markdown/reStructuredText for heading/TOC and image directive payloads.
3. Cap inbound HTTP header size at proxies and app servers, and specifically monitor/limit `baggage`, Jaeger, and OT trace propagation headers.
4. Rate-limit Synapse local user requests and federation-heavy endpoints; investigate CPU starvation, pagination failures, and abnormal federation traffic before rotating logs.
5. For wger, disable trainer-login delegation or restrict it to trusted managers; audit trainer impersonation chains and access to `/logs/` or `/stats/` for template routine IDs.
6. Treat small encrypted ZIPs produced by vulnerable pyzipper as metadata-exposed when plaintexts are low entropy; re-encrypt secrets with fixed tooling.
7. Do not run interactive scaffolding CLIs with untrusted input on shared build hosts; review shell histories and project creation logs for metacharacter payloads.

## Durable controls

- Escape rendered text and attributes at the final HTML context; regex validation must be full-string anchored when its result is inserted into CSS or HTML.
- Enforce telemetry header byte, entry-count, and fan-out budgets before propagation, not only at downstream servers.
- Session-delegation helpers must bind allowed target roles to the original principal and clear impersonation state before role changes.
- Encryption tools should avoid leaking low-entropy plaintext fingerprints such as CRC32; test metadata layouts for small and unseekable writes.
- Interactive CLI prompts are still command inputs. Pass values as argv/env/stdin to non-shell APIs, never through `exec()` string interpolation.
