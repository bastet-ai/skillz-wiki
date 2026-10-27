---
title: MLflow webhook redirect, registry source, and run-permission boundaries
---

# MLflow webhook redirect, registry source, and run-permission boundaries

Three August 19 MLflow records expose one durable operator pattern: an MLflow tracking server validates a selector (URL, run, request class) against the wrong property, so the final sink acts on a different authority than the one that was checked. The critical record is new in CISA KEV.

Primary records:

- Unauthenticated full-read SSRF via unvalidated redirect in webhook delivery: [GHSA-7gwp-5pfp-969j / CVE-2026-64849](https://github.com/advisories/GHSA-7gwp-5pfp-969j), `mlflow < 3.15.0` (pip and npm), KEV-added 2026-08-19, due 2026-09-02, with [project issue #24179](https://github.com/mlflow/mlflow/issues/24179) and [fix PR #24258](https://github.com/mlflow/mlflow/pull/24258);
- `CreateModelVersion` source validation checks path containment but not READ on the referenced `run_id`: [GHSA-gqch-g4w5-7qcw / CVE-2026-69148](https://github.com/advisories/GHSA-gqch-g4w5-7qcw), `mlflow < 3.15.0`; and
- `LogInputs` absent from the basic-auth before-request validator map: [GHSA-3p64-6gvh-82v5 / CVE-2026-69146](https://github.com/advisories/GHSA-3p64-6gvh-82v5), `mlflow < 3.15.0`.

This extends the existing MLflow surface tracked in the [May 18 MLflow webhook-URL boundary batch](2026-05-18-mcp-parser-admin-and-consensus-boundary-batch-ghsa.md), the [May 21 Fission/MLflow SSRF batch](2026-05-21-fission-mlflow-langflow-ssrf-crabbox-boundary-batch-ghsa-kev.md), and the [June 4 MLflow `/ajax-api` batch](2026-06-04-keycloak-mlflow-auth-boundary-batch-ghsa.md). The new records matter because the guard exists (PR #20747, shipped 3.10.0) yet still bypasses at the final connection step.

!!! warning "Disposable servers, owned peers, and denied sinks only"
    Use an isolated lab MLflow server on a synthetic SQLite or lab database, synthetic users, owned no-content HTTP peers, and patched/denied webhook, artifact, and lineage sinks. Never read production experiments, artifacts, or model registries; never target metadata, loopback, or private production ranges; and never complete a live model deploy or registry mutation on a shared deployment.

## Boundary map

| Surface | Caller-controlled authority | Final sink | Bounded positive |
| --- | --- | --- | --- |
| `POST /api/2.0/mlflow/webhooks/{id}/test` (default server, no auth) | webhook URL hostname | outbound HTTPS connection and reflected `response_status`/`response_body` | guard-valid public URL -> `302` to owned denied peer -> connector records final authority |
| `POST /model-versions/create` with `source_run_id` | referenced `run_id` + `source` path | stored model-version artifact URI, later `GET /model-versions/get-artifact` | containment-only check passes for a run the caller cannot READ -> denied artifact reader records the victim dir |
| `POST /runs/log-inputs` (basic-auth plugin) | target `run_id` | `DatasetInput` lineage rows in another run | authenticated non-owner write succeeds while `log-metric` on the same run returns 403 |

## 1. Webhook redirect: validation pins nothing, delivery re-resolves

The 3.10.0 guard `_validate_webhook_url` in `mlflow/utils/validation.py` checks the original URL: scheme allowlist (default `["https"]`), `socket.getaddrinfo` resolution, and `ip.is_global` for each answer when `_MLFLOW_ALLOW_PRIVATE_IPS` is unset. The resolved IP is never carried into the connection.

Delivery in `mlflow/webhooks/delivery.py` re-validates the **original** URL only, then `session.post`s with default redirect following and no IP pinning:

```text
attacker allowlisted HTTPS host
-> _validate_webhook_url passes on the original hostname
-> HTTP 302 Location: internal / loopback / metadata URL
-> requests follows the redirect; target never re-validated
-> /test returns response_status + response_body to the caller
```

The `test` route makes this full-read: the upstream response body is reflected to the caller. A default `mlflow server` (no auth, SQLite backend) has no webhook authorization at all; the only webhook auth lives in the optional basic-auth plugin's `WEBHOOK_BEFORE_REQUEST_HANDLERS`, which is not loaded by default.

### Validation harness

- Preconditions: isolated lab MLflow server `< 3.15.0` on a lab database, no shared experiments, owned no-content HTTPS peer with a controlled redirect table, and a patched webhook-session recorder that captures the final peer without ever reaching internal ranges.
- Create a webhook pointing at the owned peer. Run `POST /api/2.0/mlflow/webhooks/{id}/test` and record: validated hostname, resolved IP, redirect status/`Location`, final peer, and whether the recorder received the follow-up request.
- Bypass matrix: `302` to loopback, `302` to a public hostname that rebinds to a local sentinel between validation and connect (TOCTOU), alternate IP literal forms in `Location`, chained redirects, and a non-redirect control that must stay blocked.
- Positive evidence: the denied connector receives a request whose final peer differs from the validated peer, and `/test` reflects the owned sentinel body to the caller. Report status/body relay separately from destination control.
- Negative controls: `>= 3.15.0` behavior, `allow_redirects=False` plus redirect-target re-validation, IP-pinned sessions, and the basic-auth plugin loaded with webhook handlers present.
- Do not request cloud metadata, internal services, or other tenants' resources; the owned peer is the only allowed destination.

## 2. Registry source: containment without READ

`_validate_source_run` / `_validate_source_model` in `mlflow/server/handlers.py` verify that `source` sits inside the referenced run/model artifact directory, but they do not check that the caller has READ on that run or model. After `CreateModelVersion` succeeds (UPDATE on the registered model is required), the caller owns the model version and can read from the stored artifact directory via `GET /model-versions/get-artifact`, bypassing the experiment-level READ gate that `GET /get-artifact` enforces.

### Validation harness

- Preconditions: lab basic-auth server, two synthetic accounts, an experiment whose `default_permission` is `NO_PERMISSIONS` (or where the attacker holds no grant), and a denied artifact reader patched into the artifact-serving path.
- Alice creates run A with a synthetic marker artifact; Bob creates the registered model and calls `CreateModelVersion` with `source_run_id=A`.
- Positive evidence: the create call succeeds despite no READ on run A, and the later `get-artifact` lookup targets Alice's artifact directory at the denied reader.
- Negative controls: patched `>= 3.15.0`, a source run the caller can already read (must succeed), and a source path outside the run artifact dir (must fail containment).
- Record the permission decision for both `get-artifact` and `model-versions/get-artifact` on the same run; the bypass is the differential, not the 200 alone.

## 3. Handler-map gap: one run-write route escapes the validator

The basic-auth plugin gates handlers through `_before_request`, which looks up a validator built from the `BEFORE_REQUEST_HANDLERS` dict (protobuf request class -> validator). A class absent from the dict yields a `None` validator, and `if validator:` skips authorization entirely: any authenticated principal passes.

`LogInputs` is absent from the dict while `LogMetric`, `LogParam`, `SetTag`, and `LogBatch` are present, so `POST /api/2.0/mlflow/runs/log-inputs` (and the `/ajax-api/` variant) admits any credential and writes `DatasetInput` lineage rows into any run.

### Validation harness

- Preconditions: two synthetic accounts, two experiments, the basic-auth plugin, and a denied lineage writer recorder at the store layer.
- Confirm the control: Bob's `POST /runs/log-metric` against Alice's run returns 403.
- Then send Bob's `POST /runs/log-inputs` against Alice's run with a synthetic `dataset_inputs` record.
- Positive evidence: the recorder records the write attempt into Alice's lineage table while the metric control stays 403.
- Negative control: patched `>= 3.15.0` returns 403 for the same request.
- Do not poison real experiment lineage or use real dataset identifiers; the proof is the denied-sink record plus the 403 differential.

## Reporting notes

Lead with the crossed boundary, not the version:

- **validated webhook hostname -> unvalidated redirect final peer, body reflected to caller**
- **source-path containment -> missing READ on the referenced run, artifact read via model-version route**
- **handler presence in the validator map -> per-run UPDATE/READ bypass for one write route**

Strong reports include the exact MLflow build and auth plugin state, the route and request shape, validated value versus final peer/target, the reflected or denied-sink evidence, user-interaction requirements, and the fixed-version negative control. For the KEV-tracked SSRF, state clearly whether the server is default-unauthenticated, authed, or proxy-fronted, and which redirect/rebinding vector actually fired.

## October 6 follow-up: unauthorized artifact writes on the MPU route family (CVE-2026-2651 / GHSA-8c7q-86fq-vvmh, critical)

MLflow ≤3.10.1.dev0 in `--serve-artifacts` mode left the **multipart-upload route family `/mlflow-artifacts/mpu/*` without resource-level permission checks**, while the ordinary artifact routes were gated. Cross-user artifact overwrite → model supply-chain poisoning → code execution when a compromised model is loaded. Published late (Oct 6 updated-feed) although the CVE is older — re-surfacing with enrichment is a standing tell that a fix diff is now public.

- Durable axis: **one route family inside a gated subsystem frequently escapes the auth middleware that covers its siblings** — this page's handler-map gap (one run-write route escaping the validator) with the *upload* leg as the second example. When auditing any artifact/blob store, enumerate the multi-step upload endpoints (`/mpu/start|complete|abort`, presigned-URL minters, resumable chunks) **separately from the read/download verbs** — write paths added later for large-object support are the ones that skip the resource check. Probe on an authorized lab server with `--serve-artifacts` and auth enabled: as user B, `PUT` a marker artifact into user A's run path via each MPU verb; denial on `/mlflow-artifacts/` writes but acceptance on `/mpu/` is the finding.
- Supply-chain framing for authorized AI-stack assessments: an artifact-overwrite primitive is a **model poisoning** primitive without any registry compromise — the victim's next `mlflow.models.load_model` of an overwritten path is the execution sink. Report it as an integrity boundary, not just a broken-access-control row.

## Reviewed but not promoted here

- The `mlflow` npm/pip duplicate range entries for the three advisories were treated as one record each.
- No adjacent MLflow availability-only records were promoted in this window.

## October 20 follow-up: FileStore trace-ID traversal — the unauthenticated write primitive moved to the tracing API (wqmh/CVE-2026-53995, MLflow ≤3.17.1)

`POST /api/3.0/mlflow/traces` accepts a **crafted trace ID containing traversal sequences**; `FileStore.start_trace()` writes `trace_info.yaml`, request_metadata, and tag files at attacker-controlled paths **outside the experiment trace directory**, subject to process permissions, with no authentication required on the tracking server. Backend-shape fingerprint matters: **FileStore is the default tracking backend before 3.7.0** (opt-in after; SQLite is the newer default) — so older deployments are vulnerable with zero configuration, and the route family (`/api/3.0/mlflow/traces`) is newer than most pentesters' probe list.

- Rule extension from this page's handler-map gap: **each new API surface family (runs → experiments → traces) re-implements path construction against the store backend; the newest family is the least-audited one.** Enumerate tracing/evaluation route families (`/api/3.0/mlflow/traces*`, `/ajax-api/3.0/...` alias) separately from the classic run endpoints, then probe ID fields with `../` shapes scored on file-existence side channels in a lab FileStore. Traversal-in-identifier position, write-what-content-you-can-name (yaml/tag files) = config-write candidate chain, same deferred-execution framing as the Oct 14 ONLYOFFICE runtime.json leg — but prove only with disposable canary directories.

## October 23 follow-up: unauthenticated scorer-invoke reflection — module allowlist gates the import path but not the attribute or its kwargs (CVE-2026-115886 / [GHSA-2wqp-q3c6-ccj5](https://github.com/advisories/GHSA-2wqp-q3c6-ccj5), MLflow 3.12.0rc0–<3.17.0)

`POST /ajax-api/3.0/mlflow/scorer/invoke` has **no auth decorator** and deserializes the request body via `Scorer.model_validate_json()`, which resolves a caller-named class with `getattr(module, class_name)` behind a **module-path allowlist** (`ragas`/`deepeval`/`trulens`/`phoenix`) that constrains neither the *attribute* picked from the allowed module nor its constructor `kwargs`. With the documented-optional `trulens` + `trulens-providers-litellm` packages installed, a `model` URI outside MLflow's native registry (`openai:/...`) routes to the litellm fallback that forwards raw `api_base`/`api_key` kwargs — an unauthenticated attacker forces an outbound HTTP request to an arbitrary host with attacker-controlled headers. Full SSRF from an unauthenticated route through *constructor-kwarg passthrough*, not a URL field.

- Durable axes: (1) **an import allowlist is one of three gates — path, attribute, and kwargs. `getattr(module, X)` behind a frozenset of modules still exposes every public callable in those modules as an instantiation sink; audit reflection sites for which of the three the check actually constrains.** Grep fingerprint: `importlib.import_module(` + `getattr(` + `class(**kwargs)` in one handler. (2) **"Optional documented dependency" = deployment-shape fingerprint**, same rule as the Collabora `richdocumentscode` leg: the vuln exists only where the GenAI-eval extra is installed; probe `pip show trulens`-shaped behavior indirectly via error-text differences on the route, and state the precondition in reports. (3) **The `/ajax-api/` alias family keeps escaping auth decorators** (`@catch_mlflow_exception`/`_disable_if_artifacts_only` are not authz) — enumerate every route decorator per handler, not per blueprint, when auditing MLflow-style single-file handler maps. Validation boundary: lab server with the optional extras, owned callback endpoint as `api_base`; prove the outbound hit + header reflection only.

## October 27 follow-up: scorer-deserialization RCE via self-authored package descendant, schemeless prompt-source file read, and autolog credential spans ([GHSA-26p8-2jq9-3vq9](https://github.com/advisories/GHSA-26p8-2jq9-3vq9)/CVE-2026-116692 critical, [GHSA-m65p-9j7q-6w33](https://github.com/advisories/GHSA-m65p-9j7q-6w33)/CVE-2026-116690, [GHSA-j7qq-vr8c-xvw3](https://github.com/advisories/GHSA-j7qq-vr8c-xvw3)/CVE-2026-116691)

Published 21:26Z with full PoCs. Three legs, one product, four-plus prior MLflow waves on this page alone — the tracking page is now the operator map for the whole surface.

**1. Unauthenticated RCE: the module allowlist is satisfiable by code you upload yourself (CVE-2026-116692, feature introduced 3.12.0, advisory lists fix 3.17.0; PoC reproduced on the stock `ghcr.io/mlflow/mlflow:v3.14.0` image running uid 0, no auth, no special server option).** The deserializer check is `module_path == m or module_path.startswith(m + ".")` against the four allowed scorer roots — and MLflow's own artifact layout lets you create an *importable descendant* under an allowed root: create an experiment with `artifact_location` = `file:///usr/local/lib/python3.10/site-packages/mlflow/genai/scorers/trulens`, create a run (MLflow allocates `<artifact_location>/<run_id>/artifacts/`), upload `audit_<token>.py` into the run artifacts, then submit a serialized scorer with module path `mlflow.genai.scorers.trulens.<run_id>.artifacts.audit_<token>` to `/ajax-api/3.0/mlflow/scorer/invoke`. `importlib.import_module()` + `getattr()` + `scorer_class(**init_kwargs)` run **before** trace-ID validation, so the constructor executes server-side even though later scorer processing 500s. No existing module is overwritten — the attacker authors a *new* file inside the trusted prefix.

- **A package-name prefix is not a provenance boundary.** `startswith(allowed + ".")` only asks *where the import path says it lives*, never *who wrote the file*. If the server process can write anywhere below an allowed package — through an artifact store, cache dir, upload dir, or any earlier write primitive — the allowlist is a formality. Audit rule: for every string-prefix module/file allowlist, enumerate write primitives reachable into the allowed tree (this product handed one over on a plate via `artifact_location`); the pair (prefix gate, writable descendant) is the bug even when each leg is "by design."
- **Deserialization-before-validation ordering is the execution guarantee.** The PoC's constructor marker lands beside its own uploaded artifact and the endpoint still returns 500 — a post-constructor failure neither prevents execution nor weakens the proof. When probing reflection sinks, expect and disregard downstream errors; score on the side effect, not the status code.
- On authenticated deployments the scorer-invoke route sits behind `validate_gateway_proxy`, which returns `True` without a resource check; exploitation still needs experiment/run/artifact-write rights, so on authed targets this becomes an any-ordinary-user → server-code-exec ladder. Banding: behavior introduced in 3.12.0 (commit `02eea26`, absent from 3.11.1) — feature-introduction-commit fingerprinting beats guessing from the fix version.
- Validation boundary: pinned official image digest, container network disabled, loopback bind, inert marker-write PoC only, disposable container. Never upload importable modules to a shared or production tracking server.

**2. Arbitrary file read via a prompt-tagged model version whose source has no URL scheme (CVE-2026-116690, 3.10.0–3.16.1, fixed 3.17.0 by [PR #25870](https://github.com/mlflow/mlflow/pull/25870)).** The CVE-2026-2614 fix added a prompt branch to `CreateModelVersion` that rejects `file://` and absolute paths but **runs path validation only when the source parses with a scheme**. Schemeless values — `../../../tmp`, `.`, a plain relative name, a percent-encoded path, a Windows drive-letter path — are stored unchanged as the artifact location; `model-versions/get-artifact` then serves files from it as the server process. The tag gate keys on the *presence* of `mlflow.prompt.is_prompt`, not its value, so `value:"false"` still selects the weaker branch. Unauthenticated on default servers; under `--app-name basic-auth` any ordinary user (model creation is permitted by default RBAC) can read `basic_auth.db` / `mlflow-auth.db` — the admin password hash — plus `/etc/passwd`, `.bash_history`, on-disk config.

- **Scheme-gated validation has a no-scheme hole.** When a check branches on `urlparse(x).scheme`, every dangerous *relative* shape skips the check entirely. Battery for any stored-path field: `../../etc`, `.`, bare names, percent-encoded separators, `C:\` drive forms — across every alternate branch that reaches the same sink.
- **Boolean-ish tag/flag gates keyed on presence instead of value** are the same family as this wiki's flag-vs-enforcement drift rows: probe the flag with `false`/`0`/empty values, not just valid ones.
- Genealogy: same handler (`_create_model_version`), same route, same *route-family gap* thesis as the Aug 19 source-validation and Oct 23 scorer legs — one incomplete fix (CVE-2026-2614 → this bypass in its own replacement branch) is the strongest tell. Enumerate alternate branches created by security fixes; they inherit less scrutiny than the main path.

**3. `mlflow.crewai.autolog()` writes provider API keys into trace telemetry (CVE-2026-116691, fixed 3.17.0).** Instrumentation serializes the CrewAI `Agent.__dict__`; the `llm` object's repr contains `api_key='sk-...'` in plaintext, landing in span attributes via `_get_agent_attributes()` **and again in `mlflow.spanInputs` via `_construct_full_inputs()`'s `v.__dict__` expansion** — two independent leakage paths, and MLflow's dedicated LLM extractor already excludes `api_key`, which is the confession. Operator rules: (1) **any telemetry/observability sink attached to an LLM framework is a credential store** — from an authorized assessment, query trace/span APIs on lab runs and grep spans for `sk-`/provider key shapes; the disclosure is automatic, no app code logs it. (2) **Sanitizer allowlist ≠ serialization allowlist**: when one extractor sanitizes and a sibling broad serializer (`__dict__`/`repr`/`model_dump`) does not, fix-one-path bugs are the norm — enumerate *every* serialization path before trusting a credential-sanitization claim.

## Reviewed but not promoted here (October 27)

- The `deepmerge` prototype-poisoning low-severity GHSA (gcqx/93753 enrichment landing) is the standing prototype-pollution class — tracked, no new axis.
- No KEV movement in this window beyond the already-dispositioned 2026.10.27 catalog (1760, Brotli + Adobe Commerce legs promoted in the 20:1xZ run).
