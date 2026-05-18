# Observability, container, AI, and parser-boundary batch

Source: GitHub Security Advisories, updated 2026-05-18:
[GHSA-pgvv-q3wf-mm9m](https://github.com/advisories/GHSA-pgvv-q3wf-mm9m),
[GHSA-8rrq-wcg8-cv5q](https://github.com/advisories/GHSA-8rrq-wcg8-cv5q),
[GHSA-wp73-mwgf-4jq9](https://github.com/advisories/GHSA-wp73-mwgf-4jq9),
[GHSA-jgg6-4rpr-wfh7](https://github.com/advisories/GHSA-jgg6-4rpr-wfh7),
[GHSA-wx9m-wx4f-4cmg](https://github.com/advisories/GHSA-wx9m-wx4f-4cmg),
[GHSA-5852-phmh-8fhr](https://github.com/advisories/GHSA-5852-phmh-8fhr),
[GHSA-q62f-h9x2-gcqc](https://github.com/advisories/GHSA-q62f-h9x2-gcqc),
[GHSA-cwpj-h54c-xjpx](https://github.com/advisories/GHSA-cwpj-h54c-xjpx),
[GHSA-r73h-97w8-m54h](https://github.com/advisories/GHSA-r73h-97w8-m54h),
[GHSA-rg2x-37c3-w2rh](https://github.com/advisories/GHSA-rg2x-37c3-w2rh),
[GHSA-vp62-88p7-qqf5](https://github.com/advisories/GHSA-vp62-88p7-qqf5),
[GHSA-mf33-gv72-w2h5](https://github.com/advisories/GHSA-mf33-gv72-w2h5),
[GHSA-g2wm-735q-3f56](https://github.com/advisories/GHSA-g2wm-735q-3f56),
[GHSA-cr6r-hmj8-pr7r](https://github.com/advisories/GHSA-cr6r-hmj8-pr7r),
[GHSA-vhrh-72hq-w8m7](https://github.com/advisories/GHSA-vhrh-72hq-w8m7),
[GHSA-363w-hvwh-w7m6](https://github.com/advisories/GHSA-363w-hvwh-w7m6),
[GHSA-x86f-5xw2-fm2r](https://github.com/advisories/GHSA-x86f-5xw2-fm2r),
[GHSA-3263-v5v9-xq8q](https://github.com/advisories/GHSA-3263-v5v9-xq8q),
[GHSA-c54j-xp92-wh28](https://github.com/advisories/GHSA-c54j-xp92-wh28),
[GHSA-jxx9-px88-pj69](https://github.com/advisories/GHSA-jxx9-px88-pj69),
[GHSA-65x3-rw7q-gx94](https://github.com/advisories/GHSA-65x3-rw7q-gx94),
[GHSA-xh3c-6gcq-g4rv](https://github.com/advisories/GHSA-xh3c-6gcq-g4rv),
[GHSA-qxch-whhj-8956](https://github.com/advisories/GHSA-qxch-whhj-8956),
[GHSA-9m6v-8fxc-4r44](https://github.com/advisories/GHSA-9m6v-8fxc-4r44),
[GHSA-7fv8-6pp7-6h85](https://github.com/advisories/GHSA-7fv8-6pp7-6h85),
[GHSA-c32j-vqhx-rx3x](https://github.com/advisories/GHSA-c32j-vqhx-rx3x),
[GHSA-x7m9-mwc2-g6w2](https://github.com/advisories/GHSA-x7m9-mwc2-g6w2), and
[GHSA-p7c4-8x34-8j8f](https://github.com/advisories/GHSA-p7c4-8x34-8j8f).

This batch is durable because it hits recurring security-control seams: observability agents parsing hostile process and protocol data, container file-copy APIs crossing the host/container boundary, AI memory shared across users or poisoned by prompt content, and upload/admin parsers converting attacker-supplied metadata into code, SQL, secrets, or process crashes.

## What changed

- **OpenTelemetry eBPF Instrumentation / OBI** fixed three host-agent issues in 0.9.0: malformed PostgreSQL BIND payloads can panic the parser, Redis error text can leak into span status messages, and unsafe `fastelf` parsing can crash the agent on malformed ELF data.
- **Mistral AI packages** had a supply-chain incident: PyPI `mistralai` 2.4.6 was malicious, and several npm `@mistralai/*` releases carried broken dropper logic. Treat both as compromised package versions even where the dropper failed.
- **Spring AI** patched memory-boundary issues in 1.0.7, 1.1.6, and 2.0.0-M6: `PromptChatMemoryAdvisor` could be poisoned through prompt injection, and default conversation IDs could leak chat memory across users.
- **ImageMagick / Magick.NET** fixed PSD policy bypass and two out-of-bounds read paths in 14.13.1. These are parser boundary issues for any app accepting user images.
- **Postgrex** fixed SQL injection in `Postgrex.Notifications.listen/3` channel-name handling in 0.22.2.
- **Docker / Moby** disclosed three host-boundary problems: `docker cp` symlink/bind-mount races can create host files or redirect copies to host paths, and `PUT /containers/{id}/archive` can execute a container binary on the host. Moby v2 beta has fixes; classic Docker advisories currently list affected ranges without a patched classic release.
- **CloakBrowser** fixed unauthenticated path traversal in `cloakserve` before 0.3.28 that could delete arbitrary directories via the fingerprint parameter.
- **cowlib** added another request-header injection issue: unvalidated cookie encoding can inject headers in affected 2.9.0-2.16.1 deployments.
- **Budibase** fixed three boundary breaks in 3.38.1: CouchDB reduce injection, row-action triggers bypassing view filters, and builder-to-admin escalation through `onboardUsers` when SMTP is not configured.
- **n8n-MCP** fixed multi-tenant credential fallback in 2.51.2; requests missing tenant headers could fall back to process-level n8n credentials.
- **multiparty** fixed filename parser ReDoS, `filename*` uncaught-exception DoS, and prototype-pollution-triggered uncaught exceptions in 4.3.0.
- **Sulu** fixed API-key exposure and weak API-key/reset-token generation in 2.6.23 and 3.0.6.
- **ruby-jwt** fixed an empty-key HMAC verification bypass in 3.2.0.
- **Formie** fixed pre-auth server-side template injection in hidden fields in 2.2.20 and 3.1.24.
- **TinyIce** fixed missing authentication on WebRTC ingest in 2.5.0, preventing unauthorized stream injection.

## Operator triage

1. Treat **Mistral package versions** as incident-response scope, not routine patching. Remove PyPI `mistralai==2.4.6`, npm `@mistralai/mistralai` 2.2.2-2.2.4, `@mistralai/mistralai-azure` 1.7.1-1.7.3, and `@mistralai/mistralai-gcp` 1.7.1-1.7.3; inspect build hosts, lockfiles, caches, CI tokens, and developer machines that installed them.
2. Patch internet-facing or tenant-facing **Budibase**, **n8n-MCP**, **Formie**, **TinyIce**, and **CloakBrowser** first; these directly affect auth, tenant isolation, template execution, media ingestion, or unauthenticated filesystem operations.
3. For **Docker/Moby**, restrict Docker API/socket access to trusted operators only, disable untrusted archive/copy workflows, and watch vendor channels for fixed classic Docker trains if v2 beta is not deployable.
4. Upgrade **Spring AI** wherever chat memory or vector advisors are shared by multiple users. Assign explicit per-user/per-session conversation IDs and treat retrieved memory as untrusted prompt input.
5. Upgrade **OpenTelemetry OBI** on privileged hosts. Observability agents often run with broad process visibility; a parser crash can become a monitoring blind spot and a log/value leak can become credential disclosure.
6. Upgrade parsers and protocol helpers: Magick.NET 14.13.1+, Postgrex 0.22.2+, multiparty 4.3.0+, ruby-jwt 3.2.0+, Sulu 2.6.23/3.0.6+, and any cowlib-dependent stack once a fixed release or downstream mitigation is available.

## Replayable validation boundaries

- **Observability parser boundary:** feed malformed PostgreSQL BIND frames, Redis error strings containing secrets/control characters, and malformed ELF samples to OBI in a constrained lab; the agent must not panic, leak sensitive payloads to spans, or lose telemetry silently.
- **Container host boundary:** race `docker cp` and archive upload paths with symlink swaps, bind-mount redirections, absolute paths, and container-controlled helper binaries; host filesystem writes and host execution must be impossible for untrusted containers.
- **AI memory boundary:** run two users through Spring AI chat flows with default and explicit conversation IDs, then attempt prompt-injected memory writes and later retrieval; no cross-user memory or attacker-supplied instruction should be trusted as system context.
- **Supply-chain boundary:** install-block listed Mistral package versions in dependency resolution, CI, artifact mirrors, and developer bootstrap scripts; verify package provenance before caches are trusted.
- **Parser/upload boundary:** upload multiparty payloads with pathological filenames, `filename*` encodings, prototype keys, and ImageMagick PSD/meta/connected-component fixtures; failures must be bounded and isolated.
- **Admin and tenant boundary:** call Budibase row actions, V1 view calculations, and onboarding endpoints directly as low-privilege users and as tenants without required headers; authorization must be repeated in the action handler and credential lookup must fail closed.
- **Crypto/token boundary:** verify ruby-jwt rejects empty HMAC keys and Sulu reset/API tokens are generated with cryptographically strong randomness and never returned after use.
- **Media ingest boundary:** connect to TinyIce ingest without credentials, replay stale credentials, and spoof stream metadata; every ingest path must require authenticated, scoped authorization before media is accepted.

## Durable controls

- Run host observability agents as hostile-input parsers: minimal privileges, crash-only isolation, payload redaction before export, and alerting on agent restarts or telemetry gaps.
- Do not expose Docker sockets or archive/copy endpoints to tenants, CI jobs, or containers without a hard mediation layer; file-copy APIs are host-boundary APIs.
- For AI memory, require explicit tenant/user/session partition keys and never promote retrieved memory above untrusted user content.
- Block known-malicious package versions at the package-manager, artifact-mirror, and CI-policy layers; version removal alone does not clean compromised builders.
- Treat filenames, multipart parameters, image metadata, channel names, and template fields as programming languages until proven otherwise: canonicalize, allowlist, bound resources, and escape at the final sink.
- Make tenant credential lookup fail closed when headers or context are missing; process-wide defaults are an escalation path.
- Prefer direct action-handler tests over UI-only checks for low-code/admin platforms; hidden UI controls do not enforce authorization.
