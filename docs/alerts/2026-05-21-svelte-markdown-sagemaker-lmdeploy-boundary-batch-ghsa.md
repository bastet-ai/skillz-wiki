# SvelteKit, Markdown, SageMaker, and LM runtime-boundary batch

Source: GitHub Security Advisories REST fallback, published/updated 2026-05-21.

This batch is durable because it gives operators reusable checks for cross-user server-function batching, Markdown render sinks, ML model-artifact integrity, cloud model-serving secret exposure, and Hugging Face `trust_remote_code` deployment paths.

## What changed

- **SvelteKit `query.batch` cross-talk** — [GHSA-hgv7-v322-mmgr](https://github.com/advisories/GHSA-hgv7-v322-mmgr): vulnerable `@sveltejs/kit >=2.38.0 <=2.60.0` could, under narrow concurrent timing, merge requests from different users and resolve them under one request context. For apps that use request-scoped identity or tenant context inside batched queries, this becomes a cross-user data-disclosure primitive.
- **md-fileserver raw-HTML Markdown XSS** — [GHSA-32q2-hhr5-6qvv](https://github.com/advisories/GHSA-32q2-hhr5-6qvv) / CVE-2026-46492: vulnerable `md-fileserver <1.10.3` enables `markdown-it` raw HTML (`html: true`) and injects rendered Markdown into the page template without sanitizing or output encoding. Stored or previewed Markdown can become script execution in the application origin.
- **SageMaker Triton model-artifact integrity gap** — [GHSA-rq6v-x3j8-7qgf](https://github.com/advisories/GHSA-rq6v-x3j8-7qgf) / CVE-2026-8597: vulnerable `sagemaker >=2.199.0 <=2.257.1` and `>=3.0.0 <=3.7.1` can deserialize Triton ModelBuilder artifacts without verifying integrity. An authenticated actor with S3 write access to the model artifact path can replace model files so the next container lifecycle event executes code with the SageMaker execution role.
- **SageMaker cleartext HMAC signing key exposure** — [GHSA-7hh5-prp2-mfh5](https://github.com/advisories/GHSA-7hh5-prp2-mfh5) / CVE-2026-8596: affected ModelBuilder/Serve flows store `SAGEMAKER_SERVE_SECRET_KEY` as a model container environment variable, and SageMaker describe APIs can return it in plaintext. A principal with describe API permissions plus S3 write access can forge valid artifact integrity signatures and pivot to inference-container execution.
- **LMDeploy unconditional `trust_remote_code=True`** — [GHSA-m549-qq94-fvhg](https://github.com/advisories/GHSA-m549-qq94-fvhg) / CVE-2026-46432: vulnerable `lmdeploy <0.13.0` hardcodes `trust_remote_code=True` in Hugging Face model initialization paths. If an attacker can control the model path through deployment config, CI/CD, Kubernetes, or a managed model-submission surface, model startup can execute remote repository Python code as the LMDeploy serving process.

## Operator triage

1. Search dependency inventories for `@sveltejs/kit` versions `2.38.0` through `2.60.0`, `md-fileserver <1.10.3`, `sagemaker` in the affected 2.x/3.x ranges, and `lmdeploy <0.13.0`.
2. For SvelteKit apps, identify `query.batch()` usage that reads session, user, tenant, organization, authorization, locale, or feature-flag state from the request context.
3. For Markdown surfaces, enumerate where users can upload, edit, preview, or share `.md` content and whether rendered output is served from the same origin as authenticated application APIs.
4. For SageMaker environments, map ModelBuilder-created models, Triton inference handlers, model artifact S3 locations, execution roles, and principals that can call `DescribeModel`, `DescribeEndpointConfig`, or `DescribeModelPackage`.
5. For LMDeploy, trace every path that can set or override `model_path`: deployment manifests, Helm values, CI variables, web admin fields, model registry metadata, queue jobs, and user-submitted model IDs.

## Replayable validation boundaries

- **SvelteKit request-context isolation:** in a lab tenant, send two concurrent sessions through the same batched query path with distinct harmless marker values. Expected safe result: each session receives only its own marker. Vulnerable result: one response includes data resolved under the other request context.
- **Markdown render check:** upload or preview a benign raw-HTML callback marker such as an inert `<img>` error handler in disposable content. Expected safe result: the tag is escaped, stripped, or rendered from an isolated origin. Vulnerable result: script-capable markup survives into the authenticated application origin.
- **SageMaker describe-permission check:** using only an authorized low-privilege cloud role, call describe APIs for in-scope ModelBuilder/Serve models and verify whether `SAGEMAKER_SERVE_SECRET_KEY` or equivalent signing material is returned in plaintext. Do not exfiltrate unrelated environment values.
- **SageMaker artifact-control proof:** prove the exploit chain by showing the same principal can both write to the model artifact S3 prefix and influence or wait for a model container lifecycle event. Keep payloads inert; a marker file, redacted environment proof, or controlled import callback in a lab endpoint is enough.
- **LMDeploy model-path control:** verify whether an untrusted user or pipeline can set a Hugging Face repo ID consumed by `lmdeploy serve`. In a lab-only environment, use a harmless repository marker to demonstrate remote code loading without deploying destructive code.

## Reporting heuristics

- For SvelteKit, include the affected route/query, package version, concurrency harness, session markers, and evidence that request context crossed users or tenants.
- For Markdown XSS, include the input Markdown, rendered HTML, origin, victim role required to view it, and the application data or action reachable from that origin.
- For SageMaker, report the IAM edge as a chain: describe permissions expose signing material, S3 write permissions modify artifacts, and lifecycle/startup behavior executes the artifact with the execution role.
- For LMDeploy, show who controls `model_path`, where `trust_remote_code=True` is applied, and the privilege boundary crossed by model initialization.
- Keep validation scoped to authorized lab or tenant-owned resources. Avoid destructive model payloads, broad S3 writes, credential disclosure beyond redacted proof, or cross-tenant tests without explicit approval.

## Notes on skipped items from this scan

- The Zebra `addr` / `addrv2` deserialization advisory is a resource-exhaustion issue in a specific blockchain node context. It was not promoted because it does not add a broad, replayable Skillz operator workflow beyond parser/resource boundary triage.
