# Tomcat, ImageMagick, ML, and OBI boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-h6fc-48rj-7qqh](https://github.com/advisories/GHSA-h6fc-48rj-7qqh),
[GHSA-5mp6-jrq3-r938](https://github.com/advisories/GHSA-5mp6-jrq3-r938),
[GHSA-fv25-8xcx-gqjc](https://github.com/advisories/GHSA-fv25-8xcx-gqjc),
[GHSA-r29c-68gh-xp6x](https://github.com/advisories/GHSA-r29c-68gh-xp6x),
[GHSA-gx5v-xp9w-j4cg](https://github.com/advisories/GHSA-gx5v-xp9w-j4cg),
[GHSA-533m-3wf6-c33v](https://github.com/advisories/GHSA-533m-3wf6-c33v),
[GHSA-rcr6-g7jc-f57g](https://github.com/advisories/GHSA-rcr6-g7jc-f57g),
[GHSA-5r4x-w6p5-222q](https://github.com/advisories/GHSA-5r4x-w6p5-222q),
[GHSA-7gg8-qqx7-92g5](https://github.com/advisories/GHSA-7gg8-qqx7-92g5),
[GHSA-jcqp-6r6f-3mfx](https://github.com/advisories/GHSA-jcqp-6r6f-3mfx),
[GHSA-36wm-hprc-mcf5](https://github.com/advisories/GHSA-36wm-hprc-mcf5),
[GHSA-g5mf-wqq5-vwg6](https://github.com/advisories/GHSA-g5mf-wqq5-vwg6),
[GHSA-pfvh-m9xv-8966](https://github.com/advisories/GHSA-pfvh-m9xv-8966),
[GHSA-2799-6g5r-mmc7](https://github.com/advisories/GHSA-2799-6g5r-mmc7),
[GHSA-78cp-f66x-qmh5](https://github.com/advisories/GHSA-78cp-f66x-qmh5),
[GHSA-gpx5-7xm4-229w](https://github.com/advisories/GHSA-gpx5-7xm4-229w),
[GHSA-fq92-qc8f-482v](https://github.com/advisories/GHSA-fq92-qc8f-482v),
[GHSA-75m9-98v2-hjpm](https://github.com/advisories/GHSA-75m9-98v2-hjpm),
[GHSA-cfpg-c974-jfhq](https://github.com/advisories/GHSA-cfpg-c974-jfhq),
[GHSA-3653-68v6-rq57](https://github.com/advisories/GHSA-3653-68v6-rq57),
[GHSA-pq7c-x8g4-rvp6](https://github.com/advisories/GHSA-pq7c-x8g4-rvp6),
[GHSA-jfrm-rx66-g536](https://github.com/advisories/GHSA-jfrm-rx66-g536),
[GHSA-43g7-cwr8-q3jh](https://github.com/advisories/GHSA-43g7-cwr8-q3jh),
[GHSA-j8p6-96vp-f3r9](https://github.com/advisories/GHSA-j8p6-96vp-f3r9),
[GHSA-vvmg-8mjr-g6q3](https://github.com/advisories/GHSA-vvmg-8mjr-g6q3), and
[GHSA-962q-hwm5-52x5](https://github.com/advisories/GHSA-962q-hwm5-52x5).

This batch is durable because it repeats four defensive themes that keep appearing across very different stacks: protocol front doors must normalize and cap hostile requests before application code sees them; media and markup renderers need sandboxed parser boundaries; ML/data platforms cannot load untrusted Python objects as data; and privileged observability agents must treat traced traffic, logs, and process memory as attacker-controlled input.

## What changed

- **Apache Tomcat** fixed five issues in 9.0.118, 10.1.55, and 11.0.22: DIGEST authentication accepted unknown users with the password `null`; `LockOutRealm` handled usernames case-sensitively; the WebSocket client could forward authentication headers to a redirect target; HTTP/2 headers were exposed to Servlet applications without sufficient validation; and unauthenticated WebDAV `LOCK` / `PROPFIND` bodies were not bounded.
- **ImageMagick / Magick.NET** fixed a cluster of parser and transform issues in 14.13.1, including JP2 and MIFF heap overwrites, MSL use-after-free, IPL multi-image heap overwrite, MIFF infinite loop CPU exhaustion, MNG list-limit policy bypass, `fx` stack exhaustion, and polynomial distort over-read.
- **ML and data-science libraries** surfaced unsafe execution boundaries: Superduper query parsing used `eval`, Snorkel and PyTorch Lightning loaded attacker-provided checkpoints through `pickle`/`torch.load` defaults, and PySyft allowed approved user-submitted Python to execute server-side without strong isolation.
- **HAPI FHIR** fixed FHIRPath regex ReDoS in 6.9.7 where `matches()`, `matchesFull()`, and `replaceMatches()` compiled user-controlled regexes without complexity limits or timeouts.
- **NiceGUI** fixed two server-side rendering/resource issues in 3.12.0: Docutils file-insertion directives in `ui.restructured_text()` could read local files, and component static-resource routes could amplify unauthenticated directory requests into traceback log-volume denial of service.
- **OpenTelemetry eBPF Instrumentation / OBI** added more 0.9.0 fixes: Memcached length integer overflow and malformed MongoDB packets could crash OBI, log-enricher `writev` handling could over-read and overwrite user buffers, and Java TLS state tracking could leak memory through an unbounded insertion-order queue.

## Operator triage

1. Patch Tomcat fleet-wide to 9.0.118, 10.1.55, or 11.0.22. Prioritize internet-facing apps with DIGEST auth, WebSocket clients, HTTP/2, WebDAV, custom Realm behavior, or reverse-proxy paths that depend on Servlet header correctness.
2. Upgrade all Magick.NET packages to 14.13.1+ and verify container/base-image ImageMagick libraries are not pinned separately. Treat upload, thumbnail, PDF, avatar, office-document, and user-supplied image pipelines as exposed parser surfaces.
3. Inventory ML workflows that load checkpoints, labelers, datasets, or query expressions from users, object stores, CI artifacts, notebooks, or model registries. Block untrusted `pickle`, unsafe `torch.load`, and dynamic `eval` until provenance and sandboxing are enforced.
4. Upgrade HAPI FHIR validator modules to 6.9.7+ anywhere public or partner-submitted resources can trigger FHIRPath evaluation.
5. Upgrade NiceGUI to 3.12.0+ for public apps using `ui.restructured_text()` or dynamic component resources. Until patched, pass only trusted static reStructuredText and watch for directory-request traceback spikes.
6. Upgrade OBI / `go.opentelemetry.io/obi` to 0.9.0+ anywhere Memcached, MongoDB, Java TLS tracking, or log injection is enabled. Restart agents after abnormal panics, CPU spikes, memory growth, or corrupted application buffers.

## Replayable validation boundaries

- **Tomcat auth/protocol boundary:** regression-test unknown DIGEST users, username case variants, WebSocket redirects to a different host, malformed HTTP/2 header values, and oversized unauthenticated WebDAV bodies. Patched instances should deny, normalize, strip, validate, or cap before app code receives risky state.
- **Media parser boundary:** run malformed JP2, MIFF, IPL, MSL, MNG, and distortion/fx payloads under CPU, memory, time, file, network, and delegate restrictions. A parser crash, unbounded loop, policy bypass, or outbound helper invocation is a failed boundary even if application auth is intact.
- **ML artifact boundary:** treat checkpoints and serialized labelers as executable programs. Validate that production loaders either use safe formats/`weights_only`-style controls or run in a disposable sandbox with no secrets, writable host paths, metadata access, or network egress.
- **FHIRPath regex boundary:** send deliberately catastrophic regex patterns through validator HTTP endpoints and confirm evaluation has length, feature, and wall-clock limits.
- **Markup/file boundary:** render attacker-controlled reStructuredText and ensure `include`, `csv-table :file:`, and `raw :file:` cannot read local files before browser sanitization.
- **Observability parser boundary:** fuzz Memcached byte lengths, truncated MongoDB messages, multi-segment `writev`, and high-churn Java TLS connection state; OBI should reject or clamp without panics, buffer corruption, or unbounded heap growth.

## Durable controls

- Keep front-door protocol libraries patched as infrastructure, not app dependencies. Tomcat-like components enforce assumptions every downstream app quietly relies on.
- Treat all file/media/markup parsers as untrusted code paths. Disable dangerous delegates and file inclusion features by default, then add per-feature allowlists only where needed.
- Do not deserialize model artifacts from untrusted sources in-process. Prefer signed, content-addressed artifacts in safer formats; isolate legacy pickle/torch workflows behind short-lived workers.
- Regex evaluators exposed through domain languages need explicit complexity controls and request-level timeouts.
- Privileged telemetry agents need parser hardening, exact buffer-length accounting, bounded state, and sensitive-output isolation because a crash or leak in the observer can affect every observed workload.
