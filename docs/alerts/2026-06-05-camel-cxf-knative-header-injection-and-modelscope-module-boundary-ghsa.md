# Camel CXF/Knative header injection and ModelScope module boundary batch

Source: GitHub Security Advisories REST API, published 2026-05-19 and updated 2026-06-04.

This batch is durable because both advisories map to reusable offensive testing patterns: **transport metadata crossing into Camel internal headers** and **model/config loading crossing into Python module execution**. Use the workflows below only in authorized labs or explicitly scoped assessments.

## What changed

- **Apache Camel CXF/Knative inbound header injection** — [GHSA-8364-hfqj-pwm6](https://github.com/advisories/GHSA-8364-hfqj-pwm6) / CVE-2026-47323: `camel-cxf-rest`, `camel-cxf-transport`, and `camel-knative-http` filtered outbound Camel-internal headers but did not configure equivalent inbound filtering. An unauthenticated HTTP caller to a CXF-RS, CXF-SOAP, or Knative HTTP endpoint could inject internal header names such as `CamelExecCommandExecutable` or `CamelFileName`. The issue becomes exploitable when the route forwards that exchange to header-driven components such as `camel-exec`, `camel-file`, dynamic endpoint routing, scripting, bean invocation, or storage writers. Affected ranges are Apache Camel `>= 3.18.0, < 4.14.6` and `>= 4.15.0, < 4.18.2` for the listed packages.
- **ModelScope crafted module execution** — [GHSA-fhhq-h4hg-549x](https://github.com/advisories/GHSA-fhhq-h4hg-549x) / CVE-2025-51427: ModelScope before `1.27.0` could execute attacker-controlled Python code when a crafted configuration selected a module path under `['nnet']['module']` (reported against `dey_mini.yaml`). Treat this as a model artifact/config trust-boundary issue: if a target pipeline accepts model bundles, model configs, or benchmark artifacts from users, the config-to-import path is a code-execution primitive.

## October 5 follow-up: camel-mail consumer leg (same asymmetric-filter pattern, new attacker vector)

- **Apache Camel Camel-Mail inbound header injection** — [GHSA-2vqf-x7g4-7c2g](https://github.com/advisories/GHSA-2vqf-x7g4-7c2g) / CVE-2026-33454 (CVSS 9.4, advisory enrichment landed 2026-10-05): `MailHeaderFilterStrategy` configures only the out direction (`setOutFilterStartsWith`) and never the in direction (`setInFilterStartsWith`). Any route consuming mail via `from("imap://...")` or `from("pop3://...")` maps `Camel`-prefixed MIME headers unfiltered into the Exchange. **The attacker vector is email delivery itself**: anyone who can send a message to a monitored mailbox injects control headers such as `CamelExecCommandExecutable`, driving downstream `camel-bean`, `camel-exec`, or `camel-sql`. Affects 3.0.0 to before 4.14.6 and 4.15.0 to before 4.18.1 (fix 4.18.1/4.19.0). Same root pattern as the page's CXF/Knative headline and the prior undertow (CVE-2025-30177) / inbound-filter (CVE-2025-27636, CVE-2025-29891) lineage.
- **Operator rule:** when auditing a Camel component's `HeaderFilterStrategy`, check in/out symmetry — an `setOutFilter*` call without its `setInFilter*` sibling is the fingerprint. Then enumerate every consumer whose untrusted input is not a direct network caller but a *delivery channel*: mailboxes, queues, mail folders, ticket inboxes, webhook payloads. These channels are routinely treated as trusted because the victim's own credentials pull from them; the sender is still the attacker. Validation stays marker-only: send a lab email with a controlled `CamelFileName` marker to a route feeding a temp-dir file sink and confirm the sink filename changes; never wire `camel-exec` into the proof.

## Operator triage

1. Search Java integration inventories for Apache Camel routes exposing CXF-RS, CXF-SOAP, or Knative HTTP consumers. Prioritize routes that bridge untrusted HTTP input into internal automation, file writes, shell execution, queue publication, storage clients, or dynamic endpoints.
2. For Camel, collect component coordinates and versions for `org.apache.camel:camel-cxf-rest`, `camel-cxf-transport`, and `camel-knative-http`, plus route snippets showing the consumer endpoint and the first downstream producer that consumes Exchange headers.
3. In route definitions, flag any downstream component where header names can override configured values: `CamelExecCommandExecutable`, `CamelExecCommandArgs`, `CamelFileName`, `CamelFileNameProduced`, dynamic `toD()` URIs, script names, bean method selectors, object storage keys, or HTTP client headers.
4. Search ML/AI estates for ModelScope use in training, evaluation, inference demos, CI benchmarks, notebooks, and model-hub ingestion workers. Prioritize paths where users can upload or reference model archives, YAML configs, repository contents, or benchmark task definitions.
5. For ModelScope, collect package version, artifact source, config path, and the exact code path that calls into model/config loading. Do not run third-party model artifacts on shared infrastructure during triage.

## Replayable validation boundaries

### Camel header-injection proof

Use a disposable Camel lab route that mirrors the target component chain but writes only to a harmless marker sink.

1. Build a minimal route with a CXF-RS, CXF-SOAP, or Knative HTTP consumer and a downstream header-sensitive component. Prefer a benign file sink in a temporary directory over command execution.
2. Send a request containing a marker internal header, for example a controlled `CamelFileName: skillz-marker.txt` value, or a non-executing `CamelExecCommandExecutable` marker if the lab route does not invoke `camel-exec`.
3. Vulnerable result: the downstream component resolves the injected internal header and changes the sink filename, command field, routing target, or storage key.
4. Capture request headers, route snippet, component versions, and the marker-only downstream effect. Do not use destructive filenames, shell payloads, or production routes.

### ModelScope module-boundary proof

Keep validation to an isolated virtual machine/container with no secrets and no host mounts beyond a scratch directory.

1. Install the affected ModelScope version in a lab environment and create a minimal config derived from the target load path.
2. Replace the configured module path under the documented `['nnet']['module']`-style key with a benign local module that writes a marker file or prints a unique string.
3. Trigger the same model/config loading function used by the target pipeline.
4. Vulnerable result: the loader imports/executes the marker module because the config-selected module path is trusted.
5. Capture the config diff, package version, loader invocation, and marker output. Do not load untrusted public model artifacts directly; recreate the primitive with inert code.

## Reporting heuristics

- Frame Camel findings as an **untrusted inbound metadata to internal Exchange header** boundary, not as a generic HTTP header issue. Include the exposed consumer, the injected header name, downstream component, version range, and marker-only effect.
- For Camel routes, report exploitability only when the downstream component actually consumes the injected header. A vulnerable package with no header-sensitive route is a version finding, not a proven exploit path.
- Frame ModelScope findings as an **artifact/config to Python import/execute** boundary. Include who controls the model/config artifact, the loader path, ModelScope version, and a benign marker module proof.
- Keep proofs authorized and non-destructive. Avoid live command execution, real file overwrites, third-party model code, or capture of production secrets.

## Sources

- GitHub Advisory Database: [GHSA-8364-hfqj-pwm6 / CVE-2026-47323](https://github.com/advisories/GHSA-8364-hfqj-pwm6)
- Apache Camel security advisory: [CVE-2026-47323](https://camel.apache.org/security/CVE-2026-47323.html)
- GitHub Advisory Database: [GHSA-2vqf-x7g4-7c2g / CVE-2026-33454](https://github.com/advisories/GHSA-2vqf-x7g4-7c2g) (camel-mail, October 5 follow-up)
- GitHub Advisory Database: [GHSA-fhhq-h4hg-549x / CVE-2025-51427](https://github.com/advisories/GHSA-fhhq-h4hg-549x)
- ModelScope fix reference: [modelscope/modelscope#1333](https://github.com/modelscope/modelscope/pull/1333)
