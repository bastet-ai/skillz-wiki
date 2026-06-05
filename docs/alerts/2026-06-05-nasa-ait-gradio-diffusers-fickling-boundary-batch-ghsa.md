# NASA AIT, Gradio, Diffusers, Fickling, and identity boundary batch

Source: GitHub Security Advisories REST API, published/updated 2026-06-05.

This batch is durable because the advisories map to reusable offensive testing patterns: **unauthenticated telemetry capture APIs writing outside a log root**, **ML/web UI file-boundary and token-leak checks**, **model-loader `trust_remote_code` gate bypasses**, **pickle scanner bypass canaries**, **telco service-token scope confusion**, and **ASGI header canonicalization mismatches**. Use these workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **NASA AMMOS AIT-Core Binary Stream Capture path traversal / arbitrary append** — [GHSA-p462-prxw-mjx4](https://github.com/advisories/GHSA-p462-prxw-mjx4) / CVE-2026-47731: `ait-bsc` exposes an unauthenticated HTTP API for creating capture handlers. Path-related form fields can escape the configured log root and append attacker-controlled bytes as the `ait-bsc` process. The advisory also documents browser-to-local-network triggering when a victim on the network opens attacker-controlled JavaScript.
- **Gradio file-boundary and mocked-OAuth token leaks** — [GHSA-rhm9-gp5p-5248](https://github.com/advisories/GHSA-rhm9-gp5p-5248) / CVE-2024-51751, [GHSA-j2jg-fq62-7c3h](https://github.com/advisories/GHSA-j2jg-fq62-7c3h) / CVE-2025-23042, [GHSA-8jw3-6x8j-v96g](https://github.com/advisories/GHSA-8jw3-6x8j-v96g) / CVE-2025-48889, and [GHSA-h3h8-3v2v-rg7m](https://github.com/advisories/GHSA-h3h8-3v2v-rg7m) / CVE-2026-27167: File/UploadButton and flagging flows have allowed caller-controlled path handling, case-insensitive `blocked_paths` bypass on Windows/macOS, server-side file copies into flagged directories, and mocked OAuth routes that can place the server owner's Hugging Face token in a visitor session when OAuth components are used outside Spaces.
- **Hugging Face Diffusers `trust_remote_code` bypass** — [GHSA-j7w6-vpvq-j3gm](https://github.com/advisories/GHSA-j7w6-vpvq-j3gm) / CVE-2026-44827 and [GHSA-98h9-4798-4q5v](https://github.com/advisories/GHSA-98h9-4798-4q5v) / CVE-2026-44513: `DiffusionPipeline.from_pretrained()` could execute custom pipeline or component Python code despite `trust_remote_code=False` when code loading occurred through cross-repo `custom_pipeline`, local snapshots, cached paths, or custom component references in `model_index.json`.
- **Trail of Bits Fickling pickle-analysis bypass** — [GHSA-r7v6-mfhq-g3m2](https://github.com/advisories/GHSA-r7v6-mfhq-g3m2) / CVE-2025-67748: crafted pickle payloads using `pty.spawn()` and stack-shape tricks could be classified as `LIKELY_SAFE`, making this useful as a scanner-coverage canary for model/artifact ingestion pipelines that rely on Fickling output.
- **free5GC NRF targetNF scope-validation bypass** — [GHSA-q7c8-gfjh-8v4p](https://github.com/advisories/GHSA-q7c8-gfjh-8v4p) / CVE-2025-66719: a crafted `targetNF` value can bypass access-token scope validation and obtain arbitrary scopes in affected Network Repository Function deployments.
- **JupyterHub LTI13 JWT signature validation gap** — [GHSA-mcgx-2gcr-p3hp](https://github.com/advisories/GHSA-mcgx-2gcr-p3hp) / CVE-2023-25574: `jupyterhub-ltiauthenticator` 1.3.0 `LTI13Authenticator` did not validate JWT signatures, enabling forged LTI launch requests in deployments using that authenticator.
- **Django ASGI underscore/hyphen header spoofing** — [GHSA-mvfq-ggxm-9mc5](https://github.com/advisories/GHSA-mvfq-ggxm-9mc5) / CVE-2026-3902: `ASGIRequest` could conflate hyphenated and underscored headers, letting an attacker influence which logical header value application code sees.

## Operator triage

1. Search for AIT-Core / `ait-bsc` deployments in mission, telemetry, lab, or test networks. Prioritize unauthenticated BSC ports, default Bottle service exposure, and hosts where the process can write into project, script, or service directories.
2. Search for public or partner-accessible Gradio apps, especially ML demos with File/UploadButton inputs, flagging enabled, custom `blocked_paths`, OAuth UI components, or host-level `HF_TOKEN` / `huggingface-cli login` credentials.
3. Search Python ML pipelines for `diffusers<0.38.0` and any `DiffusionPipeline.from_pretrained()` call that accepts user-selected repos, local snapshots, cached model paths, `custom_pipeline=`, or unreviewed `model_index.json` component declarations.
4. Search artifact-ingestion services for Fickling-based pickle triage. Prioritize systems that treat `LIKELY_SAFE` as an allow decision before unpickling, model conversion, or batch analysis.
5. In telecom labs, search for free5GC NRF 1.4.0 or `github.com/free5gc/nrf<1.4.1`, then identify who can send access-token requests and whether target NF values are attacker-controlled.
6. Search learning-platform JupyterHub deployments for `jupyterhub-ltiauthenticator==1.3.0` and `LTI13Authenticator` configuration.
7. For Django ASGI apps, identify auth, proxy, tenant, or webhook code that trusts request headers where both `X-Foo-Bar` and `X_Foo_Bar` could be supplied upstream.

## Replayable validation boundaries

### AIT-Core BSC path-append canary

Use a disposable AIT-Core lab instance. Do not write to service units, shell profiles, source files, cron paths, SSH material, or production telemetry logs.

1. Start an affected `ait-bsc` version with a known `bsc.yaml` log root and a scratch directory outside that root.
2. Baseline a normal handler creation request to `/<name>/start` and confirm captures stay inside the configured log root.
3. Repeat with path-related form fields resolving to a harmless marker file under the scratch directory.
4. Vulnerable result: the marker file is created or appended outside the configured log root as the `ait-bsc` process user.
5. Capture the version, endpoint, sanitized form-field names, configured log root, resolved marker path, file owner, and network exposure. Do not publish payloads that target executable files.
6. For browser-to-local-network exposure, prove only that a same-network browser can trigger the lab marker request; do not test against real operator workstations.

### Gradio file and token-boundary canaries

Keep proofs marker-only and prefer isolated Gradio apps with no real Hugging Face token.

1. Inventory app version, exposed route prefix, enabled components, flagging state, `blocked_paths`, operating system, and OAuth components.
2. For File/UploadButton flows, submit a controlled request with a path to a lab marker file that should not have been uploaded by the session. Vulnerable result: the app returns, copies, or processes the marker content/path instead of rejecting it.
3. For `blocked_paths`, on a case-insensitive filesystem, configure a blocked marker path and retry with path-case variants. Vulnerable result: a case variant bypasses the block.
4. For flagging, use a harmless readable marker or bounded-size file and confirm whether the server copies it into the flagged directory. Do not use `/dev/urandom`, secrets, or large files.
5. For mocked OAuth, use a fake scoped HF token in the environment and visit only the lab `/login/huggingface` / callback flow. Vulnerable result: the visitor session contains the fake server token and can be decoded or replayed because the mocked-session signing secret is predictable.
6. Capture sanitized route, component type, session isolation, OS/filesystem, observed marker, and version. Redact real tokens and file contents.

### Diffusers custom-code gate proof

Use local inert modules that write only a marker under a temp directory.

1. Build two toy Hub-style repositories or local snapshots: a benign model repo and a controlled custom-pipeline/component repo containing a Python module with a marker-only import side effect.
2. Call `DiffusionPipeline.from_pretrained()` with `trust_remote_code=False` or omitted across the relevant branches: cross-repo `custom_pipeline`, local snapshot plus remote `custom_pipeline`, cached snapshot, and custom component references in `model_index.json`.
3. Vulnerable result: the marker side effect runs even though the call should have rejected remote/custom code.
4. Capture exact package version, call shape, local-vs-Hub branch, marker evidence, and exception/no-exception behavior. Do not load untrusted public model code during assessment.

### Fickling pickle scanner-coverage canary

Do not unpickle the canary in production; test the scanner decision only.

1. Generate or reuse an inert pickle canary that exercises the advisory's unsafe module path (`pty.spawn`) but points to a harmless command such as `true` in a disposable lab.
2. Feed it through the same Fickling invocation, policy wrapper, and artifact-ingestion path used by the target.
3. Vulnerable result: the system classifies the canary as `LIKELY_SAFE` or otherwise allows it through a gate that is supposed to block executable pickle behavior.
4. Capture Fickling version, policy thresholds, output JSON, downstream allow/deny decision, and whether any later stage would unpickle automatically. Do not provide weaponized pickle files in reports.

### free5GC NRF scope-boundary proof

Run only in a telecom lab or explicitly scoped private 5G environment.

1. Stand up an affected NRF with test NF identities and a non-production token audience.
2. Request a baseline access token for a scope that the test NF should not receive and confirm denial.
3. Repeat with a crafted `targetNF` value matching the advisory condition.
4. Vulnerable result: the NRF issues a token containing the otherwise-denied scope.
5. Capture request metadata, target NF value shape, issued token claims, denied baseline, version, and network role. Do not use production subscriber, core-network, or lawful-intercept data.

### JupyterHub LTI13 JWT proof

1. In a lab JupyterHub configured with `LTI13Authenticator` 1.3.0, create a fake LTI launch JWT with a valid-looking issuer/client/deployment shape but an invalid or attacker-controlled signature.
2. Send the launch through the same LTI endpoint used by the integration.
3. Vulnerable result: JupyterHub accepts the forged launch and maps it to an existing or new user identity.
4. Capture authenticator version, LTI configuration shape, sanitized claims, signature-validation evidence, resulting identity, and session creation. Do not test against real classrooms or learner accounts.

### Django ASGI header canonicalization proof

1. Place the Django ASGI app behind the same proxy path used in scope.
2. Identify an endpoint whose authorization, tenant, callback, or webhook logic reads a security-relevant header.
3. Send paired requests containing both hyphenated and underscored variants, such as `X-Scope-User` and `X_Scope_User`, with distinct benign marker values.
4. Vulnerable result: application code sees the attacker-controlled variant or disagrees with the proxy/logged header value.
5. Capture raw request, proxy behavior, Django-observed header map, application decision, and version. Do not target real impersonation headers without written scope.

## Reporting heuristics

- Frame AIT findings as **unauthenticated handler-creation crossing a log-root boundary**. Strong evidence is a normal capture inside the root versus a marker append outside the root.
- Frame Gradio findings by trust boundary: user-selected file metadata, case-insensitive ACL bypass, flagging copy sink, or mocked OAuth server-token disclosure. Redacted fake tokens and marker files are enough.
- Frame Diffusers findings as **code-load chokepoint bypass**, not merely vulnerable dependency presence. Show that `trust_remote_code=False` failed on the specific branch the target uses.
- Frame Fickling findings as **scanner coverage failure before unsafe deserialization**, especially when `LIKELY_SAFE` becomes a deployment or ingestion allow decision.
- Frame free5GC and JupyterHub findings as **token/identity assertion validation failures**. Include denied baseline and accepted forged/scope-expanded path.
- Frame Django findings as **header canonicalization disagreement**. Show which layer saw which header and why the mismatch affects a security decision.

## Sources

- GitHub Advisory Database: [GHSA-p462-prxw-mjx4 / CVE-2026-47731](https://github.com/advisories/GHSA-p462-prxw-mjx4)
- GitHub Advisory Database: [GHSA-rhm9-gp5p-5248 / CVE-2024-51751](https://github.com/advisories/GHSA-rhm9-gp5p-5248)
- GitHub Advisory Database: [GHSA-j2jg-fq62-7c3h / CVE-2025-23042](https://github.com/advisories/GHSA-j2jg-fq62-7c3h)
- GitHub Advisory Database: [GHSA-8jw3-6x8j-v96g / CVE-2025-48889](https://github.com/advisories/GHSA-8jw3-6x8j-v96g)
- GitHub Advisory Database: [GHSA-h3h8-3v2v-rg7m / CVE-2026-27167](https://github.com/advisories/GHSA-h3h8-3v2v-rg7m)
- GitHub Advisory Database: [GHSA-j7w6-vpvq-j3gm / CVE-2026-44827](https://github.com/advisories/GHSA-j7w6-vpvq-j3gm)
- GitHub Advisory Database: [GHSA-98h9-4798-4q5v / CVE-2026-44513](https://github.com/advisories/GHSA-98h9-4798-4q5v)
- GitHub Advisory Database: [GHSA-r7v6-mfhq-g3m2 / CVE-2025-67748](https://github.com/advisories/GHSA-r7v6-mfhq-g3m2)
- GitHub Advisory Database: [GHSA-q7c8-gfjh-8v4p / CVE-2025-66719](https://github.com/advisories/GHSA-q7c8-gfjh-8v4p)
- GitHub Advisory Database: [GHSA-mcgx-2gcr-p3hp / CVE-2023-25574](https://github.com/advisories/GHSA-mcgx-2gcr-p3hp)
- GitHub Advisory Database: [GHSA-mvfq-ggxm-9mc5 / CVE-2026-3902](https://github.com/advisories/GHSA-mvfq-ggxm-9mc5)
- NASA AMMOS AIT-Core advisories/source: <https://github.com/NASA-AMMOS/AIT-Core/security/advisories> and <https://github.com/NASA-AMMOS/AIT-Core>
- Gradio advisories/source: <https://github.com/gradio-app/gradio/security/advisories> and <https://github.com/gradio-app/gradio>
- Hugging Face Diffusers advisories/source: <https://github.com/huggingface/diffusers/security/advisories> and <https://github.com/huggingface/diffusers>
- Trail of Bits Fickling advisories/source: <https://github.com/trailofbits/fickling/security/advisories> and <https://github.com/trailofbits/fickling>
- free5GC NRF source: <https://github.com/free5gc/nrf>
- JupyterHub LTI Authenticator advisories/source: <https://github.com/jupyterhub/ltiauthenticator/security/advisories> and <https://github.com/jupyterhub/ltiauthenticator>
- Django security releases: <https://docs.djangoproject.com/en/dev/releases/security/>
