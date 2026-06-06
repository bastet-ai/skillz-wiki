# lxml, LangChain, Langflow, and ML/AI file-boundary checks

Source: GitHub Security Advisories REST API, updated 2026-06-06.

This batch is durable because it turns a noisy updated-advisory wave into reusable offensive validation patterns: **XML parser local-file XXE**, **URL helper SSRF guard bypasses**, **agent-builder validation code execution**, **file API path containment**, **object/tenant authorization checks**, and **untrusted ML artifact loading**. Use these workflows only in authorized labs, staging systems, or explicitly scoped assessments.

## What changed

- **lxml parser local-file XXE** — [GHSA-vfmq-68hx-4jfw](https://github.com/advisories/GHSA-vfmq-68hx-4jfw) / CVE-2026-41066: lxml `< 6.1.0` left `iterparse()` and `ETCompatXMLParser()` with `resolve_entities=True` by default, allowing untrusted XML passed to those parser entry points to resolve local external entities.
- **LangChain URL-fetch SSRF bypasses** — [GHSA-r7w7-9xr2-qq2r](https://github.com/advisories/GHSA-r7w7-9xr2-qq2r) / CVE-2026-41488 and [GHSA-fv5p-p927-qmxr](https://github.com/advisories/GHSA-fv5p-p927-qmxr) / CVE-2026-41481: `langchain-openai` image token counting validated a URL before a separate fetch, leaving a DNS-rebinding window, while `langchain-text-splitters` validated the initial URL before `requests.get()` followed redirects to unvalidated internal targets.
- **Langflow agent/file/object boundaries** — [GHSA-v8hw-mh8c-jxfc](https://github.com/advisories/GHSA-v8hw-mh8c-jxfc) / CVE-2026-33873, [GHSA-ph9w-r52h-28p7](https://github.com/advisories/GHSA-ph9w-r52h-28p7) / CVE-2026-33497, [GHSA-7grx-3xcx-2xv5](https://github.com/advisories/GHSA-7grx-3xcx-2xv5) / CVE-2026-33484, [GHSA-g2j9-7rj2-gm6c](https://github.com/advisories/GHSA-g2j9-7rj2-gm6c) / CVE-2026-33309, [GHSA-f43r-cc68-gpx4](https://github.com/advisories/GHSA-f43r-cc68-gpx4) / CVE-2025-68478, and [GHSA-rf6x-r45m-xv3w](https://github.com/advisories/GHSA-rf6x-r45m-xv3w) / CVE-2026-33053: updated advisories describe generated component-code execution during Agentic Assistant validation, unauthenticated profile-picture traversal to server files, unauthenticated image download IDOR, authenticated multipart/file-path write issues, flow `fs_path` arbitrary writes, and API-key deletion without ownership checks.
- **MLflow model-artifact authorization** — [GHSA-46r5-x6jq-v8g6](https://github.com/advisories/GHSA-46r5-x6jq-v8g6) / CVE-2026-33866: MLflow `<= 3.10.1` exposed an AJAX endpoint for saved model artifact downloads without enforcing experiment permissions.
- **MindsDB file ingestion path boundaries** — [GHSA-qqhf-pm3j-96g7](https://github.com/advisories/GHSA-qqhf-pm3j-96g7) / CVE-2025-68472 and [GHSA-6xw9-2p64-7622](https://github.com/advisories/GHSA-6xw9-2p64-7622) / CVE-2026-2531: MindsDB file-upload/import paths included arbitrary file reads through JSON upload path handling and an SSRF-class issue in filename/source handling.
- **Untrusted ML artifact loading** — [GHSA-36rr-ww3j-vrjv](https://github.com/advisories/GHSA-36rr-ww3j-vrjv) / CVE-2025-9905, [GHSA-6vm5-6jv9-rjpj](https://github.com/advisories/GHSA-6vm5-6jv9-rjpj) / CVE-2025-58756, [GHSA-p8cm-mm2v-gwjm](https://github.com/advisories/GHSA-p8cm-mm2v-gwjm) / CVE-2025-58757, and [GHSA-g48c-2wqr-h844](https://github.com/advisories/GHSA-g48c-2wqr-h844) / CVE-2026-28277: Keras `.h5/.hdf5` loading ignores the `safe_mode=True` expectation, MONAI checkpoint/pickle utilities can execute during deserialization, and LangGraph checkpoint loading can reconstruct unsafe Python objects if an attacker can write checkpoint bytes.

## Operator triage

1. Search code, dependency manifests, containers, notebooks, and internal tools for the exact parser/helper entry points, not just package names:
   - `lxml.etree.iterparse(` and `lxml.etree.ETCompatXMLParser(`;
   - `HTMLHeaderTextSplitter.split_text_from_url(`;
   - `get_num_tokens_from_messages` usage with remote `image_url` content;
   - Langflow deployments exposing `/api/v1/files/`, `/api/v2/files/`, `/api/v1/flows`, or Agentic Assistant routes;
   - MLflow deployments with multi-user experiment boundaries and saved model artifact downloads;
   - MindsDB file upload/import APIs;
   - ML pipelines loading `.h5`, `.hdf5`, PyTorch checkpoints, MONAI bundles, pickled dataset metadata, or LangGraph checkpoints from user-writable stores.
2. Prioritize internet-facing or shared-tenant AI/ML tooling where users can submit URLs, XML, model files, checkpoints, flows, or uploaded files.
3. Separate **blind reachability** from **data exfiltration** for SSRF. LangChain image token counting can usually prove internal reachability through timing/errors only; `HTMLHeaderTextSplitter.split_text_from_url()` can become data exfiltration if returned `Document` content is exposed to the requester.
4. For file-read/write issues, prove path containment failure with disposable canary files in a lab directory. Do not read real secrets such as JWT signing keys, cloud credentials, `/etc/shadow`, database files, or production model artifacts.
5. For untrusted artifact loading, treat model/checkpoint imports as code-loading surfaces. Strong reports identify who can supply the artifact, where it is stored, and which runtime identity loads it.

## Replayable validation boundaries

### lxml `iterparse()` / `ETCompatXMLParser()` XXE canary

Use a local harness or an in-scope import feature that parses untrusted XML. Avoid reading sensitive system files.

1. Create a disposable marker file inside a temp directory, for example `/tmp/skillz-lxml-marker.txt`, containing a unique non-secret string.
2. Build XML with an external entity pointing to that marker file and a harmless root element that references the entity.
3. Exercise only the suspected parser path: `iterparse()` or `ETCompatXMLParser()` under the application configuration.
4. Vulnerable result: the parsed output, error message, log, or downstream object contains the marker string from the local file.
5. Capture lxml version, parser constructor arguments, XML feature/import endpoint, marker path, and proof that the marker came from the local filesystem. Do not include real local file contents in the report.

### LangChain SSRF redirect and DNS-rebinding guards

Use an attacker-controlled test domain and a listener you own. Keep all internal targets in a lab network.

1. For `HTMLHeaderTextSplitter.split_text_from_url()`, serve a public URL that returns a `302` to a lab-only internal HTTP endpoint with a unique HTML marker.
2. Vulnerable result: the returned `Document` objects contain the internal marker even though the initial URL passed SSRF validation as public.
3. For `langchain-openai` image token counting, use a controlled hostname whose DNS answer changes between validation and fetch, and return a tiny valid image from the lab-only target.
4. Vulnerable result: timing, errors, or successful image-dimension processing show the fetch reached the post-validation lab target.
5. Capture package version, helper call site, supplied URL, redirect chain or DNS answers, and whether response content was exposed to the user. Avoid testing cloud metadata or non-owned internal services.

### Langflow file, agent, and object-boundary canaries

Use a disposable Langflow instance or explicitly scoped staging deployment. Do not test public instances without written authorization.

1. Fingerprint version and route exposure for `/api/v1/files/profile_pictures/`, `/api/v1/files/images/`, `/api/v2/files/`, `/api/v1/flows`, `/api/v1/api_key/`, and Agentic Assistant endpoints.
2. For file reads, attempt to read only a lab marker file intentionally placed under a non-sensitive path. Vulnerable result: traversal returns the marker through the profile-picture route.
3. For image IDOR, create two lab users and two lab flows. Upload a harmless image as user B, then request it without credentials or as user A using B's `flow_id` and filename. Vulnerable result: HTTP 200 and the image bytes cross the user boundary.
4. For file writes, use a filename or `fs_path` that targets a disposable directory owned by the test instance, then verify whether a harmless marker file is created outside the intended storage directory. Do not write into startup hooks, application source, SSH directories, cron paths, or other execution-sensitive locations.
5. For Agentic Assistant validation, keep payloads side-effect-free: use generated component code that returns a static marker or raises a controlled validation-time exception proving server-side instantiation. Do not execute shell commands or open network connections.
6. For API-key deletion IDOR, create two lab users and disposable API keys. Attempt deletion of user B's key while authenticated as user A. Vulnerable result: B's key state changes.
7. Capture route, auth role, request IDs, before/after object ownership, storage base path, and sanitized responses. Redact JWTs, API keys, flow secrets, and uploaded content.

### MLflow and MindsDB file-access canaries

1. For MLflow, create two experiments with separate lab users. Save a harmless model artifact in experiment B, then request the affected AJAX artifact endpoint as a user without experiment B permissions.
2. Vulnerable result: the unauthorized user downloads the artifact bytes or metadata.
3. For MindsDB, place a disposable marker file in a non-sensitive location. Exercise JSON file-upload/import behavior and SQL query access only against that marker.
4. Vulnerable result: the marker content becomes queryable through MindsDB file storage or a URL/file source reaches a lab-only listener unexpectedly.
5. Capture version, endpoint, auth state, experiment/file IDs, and authorization expectations. Avoid moving or disclosing real files.

### ML artifact deserialization canaries

Run these only in throwaway containers or CI sandboxes without credentials.

1. Keras: verify whether the application accepts `.h5/.hdf5` uploads or pull-from-URL model imports while assuming `safe_mode=True` protects loading.
2. MONAI: identify checkpoint loading and `pickle_operations(..., is_encode=False)` paths reachable from user-controlled datasets, bundles, or transforms.
3. LangGraph: identify persistent checkpointer stores where an attacker or lower-privileged tenant can write checkpoint bytes that a higher-value runtime later resumes.
4. Use inert canaries: a deliberately invalid object that raises a recognizable exception, writes a marker inside the throwaway container's temp directory, or reaches a local-only mock function. Do not use payloads that spawn shells, fetch remote code, or access secrets.
5. Vulnerable result: model/checkpoint loading causes the canary side effect or unsafe object reconstruction in the runtime that trusted the artifact.
6. Capture artifact source, loader call, runtime identity, sandbox isolation, and whether the artifact crosses trust boundaries.

## Reporting heuristics

- Frame lxml findings as **parser entry-point configuration**, not generic XML risk. Reports should name the exact constructor and prove default entity resolution on the vulnerable path.
- Frame LangChain findings as **SSRF guard bypass by redirect or DNS rebinding**. Separate blind probe impact from returned-content impact.
- Frame Langflow findings around the crossed boundary: unauthenticated file read, cross-user object access, authenticated storage escape, or validation-time code execution.
- Frame MLflow and MindsDB findings as **artifact/file access control and path containment**. Strong evidence uses two lab principals or a disposable marker file.
- Frame ML artifact deserialization as **untrusted artifact execution surface**. The most useful bug-bounty reports show a realistic artifact ingestion path, not just a local library PoC.
- Ollama DoS/divide-by-zero, Python-Markdown exception, Mayan/Weblate/MLX disclosure or memory-safety items, and older generic XSS/DoS/imported CVEs in the same updated-feed wave were reviewed but not promoted here because they were availability-only, sparse, local/library-only without a distinct operator workflow, or already covered by stronger patterns above.

## Sources

- GitHub Advisory Database: [GHSA-vfmq-68hx-4jfw / CVE-2026-41066](https://github.com/advisories/GHSA-vfmq-68hx-4jfw)
- lxml advisory/source: <https://github.com/lxml/lxml/security/advisories> and <https://github.com/lxml/lxml>
- GitHub Advisory Database: [GHSA-r7w7-9xr2-qq2r / CVE-2026-41488](https://github.com/advisories/GHSA-r7w7-9xr2-qq2r)
- GitHub Advisory Database: [GHSA-fv5p-p927-qmxr / CVE-2026-41481](https://github.com/advisories/GHSA-fv5p-p927-qmxr)
- LangChain source/advisories: <https://github.com/langchain-ai/langchain/security/advisories> and <https://github.com/langchain-ai/langchain>
- GitHub Advisory Database: [GHSA-v8hw-mh8c-jxfc / CVE-2026-33873](https://github.com/advisories/GHSA-v8hw-mh8c-jxfc)
- GitHub Advisory Database: [GHSA-ph9w-r52h-28p7 / CVE-2026-33497](https://github.com/advisories/GHSA-ph9w-r52h-28p7)
- GitHub Advisory Database: [GHSA-7grx-3xcx-2xv5 / CVE-2026-33484](https://github.com/advisories/GHSA-7grx-3xcx-2xv5)
- GitHub Advisory Database: [GHSA-g2j9-7rj2-gm6c / CVE-2026-33309](https://github.com/advisories/GHSA-g2j9-7rj2-gm6c)
- GitHub Advisory Database: [GHSA-f43r-cc68-gpx4 / CVE-2025-68478](https://github.com/advisories/GHSA-f43r-cc68-gpx4)
- GitHub Advisory Database: [GHSA-rf6x-r45m-xv3w / CVE-2026-33053](https://github.com/advisories/GHSA-rf6x-r45m-xv3w)
- Langflow source/advisories: <https://github.com/langflow-ai/langflow/security/advisories> and <https://github.com/langflow-ai/langflow>
- GitHub Advisory Database: [GHSA-46r5-x6jq-v8g6 / CVE-2026-33866](https://github.com/advisories/GHSA-46r5-x6jq-v8g6)
- MLflow source/advisories: <https://github.com/mlflow/mlflow/security/advisories> and <https://github.com/mlflow/mlflow>
- GitHub Advisory Database: [GHSA-qqhf-pm3j-96g7 / CVE-2025-68472](https://github.com/advisories/GHSA-qqhf-pm3j-96g7)
- GitHub Advisory Database: [GHSA-6xw9-2p64-7622 / CVE-2026-2531](https://github.com/advisories/GHSA-6xw9-2p64-7622)
- MindsDB source/advisories: <https://github.com/mindsdb/mindsdb/security/advisories> and <https://github.com/mindsdb/mindsdb>
- GitHub Advisory Database: [GHSA-36rr-ww3j-vrjv / CVE-2025-9905](https://github.com/advisories/GHSA-36rr-ww3j-vrjv)
- GitHub Advisory Database: [GHSA-6vm5-6jv9-rjpj / CVE-2025-58756](https://github.com/advisories/GHSA-6vm5-6jv9-rjpj)
- GitHub Advisory Database: [GHSA-p8cm-mm2v-gwjm / CVE-2025-58757](https://github.com/advisories/GHSA-p8cm-mm2v-gwjm)
- GitHub Advisory Database: [GHSA-g48c-2wqr-h844 / CVE-2026-28277](https://github.com/advisories/GHSA-g48c-2wqr-h844)
- Keras, MONAI, and LangGraph sources: <https://github.com/keras-team/keras>, <https://github.com/Project-MONAI/MONAI>, and <https://github.com/langchain-ai/langgraph>
