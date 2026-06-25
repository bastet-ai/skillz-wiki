# Agent checkpoint, proxy identity, certificate control-plane, and appliance boundary checks

Source: hourly offensive-security scan, 2026-06-25. Primary entries: GitHub Advisory Database [GHSA-fjqc-hq36-qh5p](https://github.com/advisories/GHSA-fjqc-hq36-qh5p) / CVE-2026-48775, [GHSA-w39p-vh2g-g8g5](https://github.com/advisories/GHSA-w39p-vh2g-g8g5) / CVE-2026-48776, [GHSA-g697-2xrc-gc46](https://github.com/advisories/GHSA-g697-2xrc-gc46) / CVE-2026-9291, [GHSA-qcqw-jwxc-2hqg](https://github.com/advisories/GHSA-qcqw-jwxc-2hqg) / CVE-2026-48508, [GHSA-3fxj-6jh8-hvhx](https://github.com/advisories/GHSA-3fxj-6jh8-hvhx), [GHSA-rjr7-jggh-pgcp](https://github.com/advisories/GHSA-rjr7-jggh-pgcp), [GHSA-9g5q-2w5x-hmxf](https://github.com/advisories/GHSA-9g5q-2w5x-hmxf), CISA KEV [CVE-2026-20230](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) with the [Cisco advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW), and CISA KEV [CVE-2026-12569](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) with the [PTC advisory](https://www.ptc.com/en/support/article/CS473270).

These items are durable for operators because they expose reusable boundaries: agent checkpoint stores crossing into runtime deserialization, SDK identifiers crossing into URL paths, shared job-result storage crossing into pickle loading, empty authorization requirements turning into allow-all certificate control-plane access, user-controlled forwarding headers crossing into trusted client IPs, and appliance HTTP inputs crossing into SSRF/file-write or deserialization RCE paths.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-fjqc-hq36-qh5p](https://github.com/advisories/GHSA-fjqc-hq36-qh5p) / CVE-2026-48775 | `langgraph-checkpoint` default `JsonPlusSerializer` | checkpoint bytes at rest can be reconstructed as Python objects when workers resume state | Treat checkpoint stores as code-adjacent control planes; test only with disposable checkpointers and inert deserialization canaries. |
| [GHSA-w39p-vh2g-g8g5](https://github.com/advisories/GHSA-w39p-vh2g-g8g5) / CVE-2026-48776 | `langgraph-sdk` resource identifiers | caller-supplied IDs are interpolated into URL templates without format enforcement | Hunt for SDK callers that pass end-user IDs into resource methods while upstream auth is path-prefix based. |
| [GHSA-g697-2xrc-gc46](https://github.com/advisories/GHSA-g697-2xrc-gc46) / CVE-2026-9291 | Amazon Braket SDK `job.result()`, `load_job_result()`, and `load_job_checkpoint()` | S3 job-result metadata can select `pickled_v4`, causing `pickle.loads()` on result values | Validate ML/quantum job output buckets as execution-adjacent supply-chain stores, using marker-only results. |
| [GHSA-qcqw-jwxc-2hqg](https://github.com/advisories/GHSA-qcqw-jwxc-2hqg) / CVE-2026-48508 | Lemur `StrictRolePermission` / `AuthorityCreatorPermission` | unset flags created Flask-Principal permissions with zero `Need`s, and empty needs allow every authenticated identity | Test certificate-manager endpoints for **auth-present but role-requirement-empty** behavior with read-only users. |
| [GHSA-3fxj-6jh8-hvhx](https://github.com/advisories/GHSA-3fxj-6jh8-hvhx), [GHSA-rjr7-jggh-pgcp](https://github.com/advisories/GHSA-rjr7-jggh-pgcp), [GHSA-9g5q-2w5x-hmxf](https://github.com/advisories/GHSA-9g5q-2w5x-hmxf) | `go-chi/chi` `middleware.RealIP` | `True-Client-IP`, `X-Real-IP`, or leftmost `X-Forwarded-For` can replace `r.RemoteAddr` without trusted-proxy validation | Check IP ACLs, rate limits, audit attribution, and admin route gates that trust framework-derived client IPs. |
| [CVE-2026-20230](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Cisco Unified Communications Manager / SME | crafted unauthenticated HTTP requests can trigger SSRF through the appliance and write files for later root escalation | Scope perimeter UC appliances for route-level SSRF validation with owned callbacks and no production file writes. |
| [CVE-2026-12569](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | PTC Windchill PDMLink / FlexPLM | untrusted deserialization exposed as critical remote code execution in product lifecycle systems | Prioritize version and exposure confirmation, then reproduce only in approved labs with non-executing deserialization canaries. |

## Operator triage

1. **Storage write is often runtime control.** Checkpoint stores, job-result buckets, and model/workflow artifacts should be treated as inputs to future code paths, not passive data.
2. **Identifier validation belongs before SDK calls.** UUID-looking fields, run IDs, thread IDs, checkpoint IDs, and resource IDs should reject `/`, `%2f`, `..`, `?`, `#`, encoded separators, and mixed-normalization variants before reaching URL-building helpers.
3. **Empty role lists are authorization decisions.** Look for wrappers where feature flags decide which roles to require; if the disabled branch constructs a permission object with no requirements, verify whether the framework treats it as allow-all.
4. **Forwarded IP headers are hostile unless a trusted proxy boundary is enforced.** If the app is directly reachable, client-supplied `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` should not influence route gates or throttles.
5. **Appliance KEVs need product ownership first.** For Cisco Unified CM and Windchill/FlexPLM, collect version, exposed route, and role/reachability evidence before any SSRF or deserialization proof.

## Replayable validation boundaries

### LangGraph checkpoint and resource-ID harness

- Preconditions: explicit authorization, disposable LangGraph deployment, synthetic threads/checkpoints, and a backing store that contains no production prompts, credentials, or customer state.
- For checkpoint loading, seed only inert canary records that prove serializer type reconstruction or blocked reconstruction. Do not attempt shell execution, secret reads, or worker environment access.
- For SDK URL construction, pass route-shaped identifiers such as `../canary`, `%2fcanary`, `a?x=y`, and UUID negative controls through the application layer that normally calls the SDK.
- Evidence should include package versions, SDK method, original identifier, final requested path observed by a mock server or controlled proxy, authorization decision point, and fixed-version/validated-ID negative controls.

### Shared job-result deserialization harness

- Preconditions: authorized Braket-style lab job, disposable S3 bucket/prefix, synthetic result files, and a client host with no sensitive environment variables.
- Write a marker-only `results.json` that toggles `dataFormat` to a serialized format and confirms whether the client attempts unsafe deserialization when `job.result()` or equivalent loaders run.
- Use non-executing pickle detection where possible, such as a local harness that records deserializer selection before object execution. If a live SDK proof is required, keep it inside an isolated throwaway environment.
- Evidence should show bucket/prefix permissions, result metadata, loader call path, canary observation, and patched-version negative control.

### Lemur certificate control-plane authorization harness

- Preconditions: lab Lemur instance, disposable read-only user, synthetic domain/certificate/notification records, and no production CAs or notification targets.
- As the read-only user, attempt only inert create/update actions: synthetic domain entry, canary certificate upload, and notification URL pointing to an owned callback.
- Record whether endpoints guarded by `StrictRolePermission` or `AuthorityCreatorPermission` accept the request when strict role flags are unset.
- Do not create real root CAs, alter production certificate authorities, or point notification SSRF checks at internal services.

### chi RealIP trust-boundary harness

- Preconditions: owned app or lab service using `go-chi/chi` `middleware.RealIP`, plus a harmless route whose behavior depends on client IP.
- Send paired requests with and without forged `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` headers. Include a direct-to-origin test and, if applicable, a test through the real trusted proxy.
- Validate effects on IP ACLs, rate limits, logs, and any admin/debug route gate. Keep target routes harmless and avoid bypassing real customer controls.
- Evidence should include network path, proxy headers, observed `RemoteAddr`, route decision, and a trusted-proxy-aware negative control.

### Appliance KEV validation boundaries

- Cisco Unified CM / SME: prove only route reachability and SSRF callback behavior in approved environments. Use owned callback domains and synthetic markers; do not write files to production appliances or chain to root escalation.
- PTC Windchill / FlexPLM: confirm affected product/version and deserialization exposure. Any payload testing belongs in a vendor lab or customer-approved clone with inert canaries only; do not run public RCE payloads or touch production PLM data.

## Reporting notes

- Lead with the boundary: **checkpoint store to worker deserialization**, **resource ID to URL path**, **job-result bucket to pickle load**, **empty permission needs to allow-all**, **forwarded header to trusted IP**, **appliance HTTP input to SSRF/file-write**, or **PLM deserialization to RCE**.
- Include exact package/product versions, route or method name, caller role, canary value, and negative controls.
- Keep all artifacts synthetic: disposable checkpoints, marker job results, read-only lab users, fake certificates, owned callbacks, and harmless route canaries.
