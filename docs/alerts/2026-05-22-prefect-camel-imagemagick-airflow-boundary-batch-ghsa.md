# Prefect, Camel, ImageMagick, and Airflow boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-22.

This batch is durable because the advisories map to reusable operator checks: workflow-orchestrator auth and webhook boundaries, Camel internal-header filtering across non-HTTP transports, exposed ImageMagick distributed-cache services, and Airflow provider credential capture over unauthenticated STARTTLS.

## What changed

- **Prefect health-check auth bypass** — [GHSA-6rr6-v7cj-mxpg](https://github.com/advisories/GHSA-6rr6-v7cj-mxpg) / CVE-2026-7722: Prefect up to 3.6.21 exposed an auth bypass through an `endswith()` health-check exemption around `/api/health`. The public exploit signal makes this useful for API boundary testing, not just version triage.
- **Prefect unauthenticated event injection** — [GHSA-hvph-5985-r63v](https://github.com/advisories/GHSA-hvph-5985-r63v) / CVE-2026-7723: Prefect up to 3.6.13 allowed remote unauthenticated manipulation of the `/api/events/in` WebSocket endpoint.
- **Prefect restricted-URL DNS-rebinding bypass** — [GHSA-p3pq-hxmr-vqqr](https://github.com/advisories/GHSA-p3pq-hxmr-vqqr) / CVE-2026-7724: Prefect up to 3.6.28.dev1 had a TOCTOU issue in `validate_restricted_url` for webhook/notification URL validation.
- **Prefect GitRepository pull-step argument injection** — [GHSA-6rcx-55r6-jx65](https://github.com/advisories/GHSA-6rcx-55r6-jx65) / CVE-2026-7725: Prefect up to 3.6.25.dev6 let controlled `commit_sha` / `directories` values reach Git command arguments in `src/prefect/runner/storage.py`.
- **Apache Camel non-HTTP header filter bypass to downstream RCE / file write** — [GHSA-jg2m-9x48-3gvj](https://github.com/advisories/GHSA-jg2m-9x48-3gvj) / CVE-2026-40453: the CVE-2025-27636 fix lowercased HTTP header filtering, but five non-HTTP strategies did not get the same treatment: `camel-jms` `JmsHeaderFilterStrategy`, `ClassicJmsHeaderFilterStrategy`, `camel-sjms` `SjmsHeaderFilterStrategy`, `camel-coap` `CoAPHeaderFilterStrategy`, and `camel-google-pubsub` `GooglePubsubHeaderFilterStrategy`. Because Camel Exchange headers are case-insensitive, case-variant internal headers can survive filtering and later drive `camel-exec`, `camel-file`, or other header-sensitive producers.
- **ImageMagick distributed pixel cache server issues** — [GHSA-p93h-f2jc-477j](https://github.com/advisories/GHSA-p93h-f2jc-477j) / CVE-2026-46692, [GHSA-4g75-9r48-jf92](https://github.com/advisories/GHSA-4g75-9r48-jf92) / CVE-2026-46693, [GHSA-2rgj-gx5x-f62w](https://github.com/advisories/GHSA-2rgj-gx5x-f62w) / CVE-2026-47165, and [GHSA-6gxq-f64p-5w6f](https://github.com/advisories/GHSA-6gxq-f64p-5w6f) / CVE-2026-47166: attackers who can connect to `magick -distribute-cache` can hit heap over-read/overwrite, file-descriptor hijack race, and weak authentication-model boundaries.
- **Airflow SMTP provider STARTTLS credential capture** — [GHSA-x8mh-94wc-33gv](https://github.com/advisories/GHSA-x8mh-94wc-33gv) / CVE-2026-41016: `apache-airflow-providers-smtp` called `smtplib.SMTP.starttls()` without an SSL context, so a positioned attacker could present a self-signed certificate and capture SMTP credentials during the subsequent `login()`.

## Operator triage

1. Search scope inventories for externally or internally reachable Prefect APIs, especially self-hosted orchestration panels, automation runners, webhook/notification configurations, and projects that clone deployments from Git.
2. For Prefect, collect version, bind address, auth mode, reverse-proxy path rules, WebSocket exposure, webhook destinations, and deployment storage configuration. Treat event injection, restricted-URL validation, and Git pull steps as separate primitives that may chain only in specific deployments.
3. Search integration estates for Camel routes that consume JMS, SJMS, CoAP, or Google Pub/Sub messages and forward exchanges into header-driven producers such as `exec`, `file`, dynamic endpoint routing, bean invocation, scripting, HTTP clients, or storage writers.
4. For Camel, inspect route definitions and broker permissions for any untrusted producer path. The key smell is transport metadata becoming Camel internal headers after incomplete filtering.
5. Search exposed services and container command lines for `magick -distribute-cache`, unusual ImageMagick cache-listening ports, or image-processing worker fleets that bind cache services beyond localhost.
6. Search Airflow deployments for SMTP provider package versions, SMTP connection definitions, and network positions where an authorized test can intercept worker-to-SMTP STARTTLS traffic.

## Replayable validation boundaries

- **Prefect auth-bypass proof:** in an authorized lab or test instance, request a harmless normally-protected endpoint through a path form that matches the health-check exemption behavior. Vulnerable result: the request is treated as health-check-equivalent without normal auth. Capture only status codes and redacted headers.
- **Prefect event-injection proof:** connect to `/api/events/in` on a test instance and send a marker event with no operational side effect. Vulnerable result: the event is accepted without authentication. Do not inject events into production automation streams unless explicitly approved.
- **Prefect DNS-rebinding proof:** use a controlled domain whose initial answer passes restricted-URL validation and whose later answer resolves to a lab-only blocked address. Vulnerable result: validation and fetch/connect use different addresses. Keep callbacks to your own listener.
- **Prefect Git argument proof:** create a disposable deployment using a benign Git option in the controlled field that produces a visible non-sensitive error or marker. Do not use command-execution payloads against shared runners.
- **Camel header-bypass proof:** in a lab route, publish a JMS/SJMS/CoAP/PubSub message with case-variant `CamelExecCommandExecutable`, `CamelFileName`, or equivalent internal headers and forward it only to a harmless marker sink. Vulnerable result: a downstream component resolves the canonical internal header despite filtering.
- **ImageMagick cache-service proof:** limit validation to service discovery, banner/protocol reachability, and version confirmation unless crash or memory-corruption testing is explicitly in scope. A reachable unauthenticated distributed cache service is already a strong finding.
- **Airflow SMTP proof:** with written approval, configure a test SMTP endpoint or lab MITM position and show that the worker accepts an untrusted STARTTLS certificate before sending credentials. Use disposable credentials only.

## Reporting heuristics

- Frame Prefect findings by primitive and trust boundary: path-auth exemption, unauthenticated WebSocket event ingress, URL-validation TOCTOU, or Git argument construction.
- For Camel, include the exact component (`camel-jms`, `camel-sjms`, `camel-coap`, or `camel-google-pubsub`), producer permission required, downstream header-sensitive component, and one redacted case-variant header proof.
- For ImageMagick, report exposed `magick -distribute-cache` as a network service boundary issue, not a generic image-upload parser bug. Include bind address, network path, version, and whether authentication/challenge-response is present.
- For Airflow, report the exploit path as network-positioned SMTP credential capture from worker egress, with package version, connection path, and proof using throwaway credentials.
- Keep all proofs within authorized test infrastructure; avoid crashing shared services, reading real secrets, or capturing live production credentials.
