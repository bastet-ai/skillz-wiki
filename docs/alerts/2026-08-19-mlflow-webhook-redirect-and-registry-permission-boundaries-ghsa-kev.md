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
