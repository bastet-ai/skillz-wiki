# Agent checkpoint, SSH agent, proxy identity, certificate control-plane, and appliance boundary checks

Source: hourly offensive-security scan, 2026-06-25. Initial entries: GitHub Advisory Database [GHSA-fjqc-hq36-qh5p](https://github.com/advisories/GHSA-fjqc-hq36-qh5p) / CVE-2026-48775, [GHSA-w39p-vh2g-g8g5](https://github.com/advisories/GHSA-w39p-vh2g-g8g5) / CVE-2026-48776, [GHSA-g697-2xrc-gc46](https://github.com/advisories/GHSA-g697-2xrc-gc46) / CVE-2026-9291, [GHSA-qcqw-jwxc-2hqg](https://github.com/advisories/GHSA-qcqw-jwxc-2hqg) / CVE-2026-48508, [GHSA-3fxj-6jh8-hvhx](https://github.com/advisories/GHSA-3fxj-6jh8-hvhx), [GHSA-rjr7-jggh-pgcp](https://github.com/advisories/GHSA-rjr7-jggh-pgcp), [GHSA-9g5q-2w5x-hmxf](https://github.com/advisories/GHSA-9g5q-2w5x-hmxf), CISA KEV [CVE-2026-20230](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) with the [Cisco advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-ssrf-cXPnHcW), and CISA KEV [CVE-2026-12569](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) with the [PTC advisory](https://www.ptc.com/en/support/article/CS473270).

June 25 late update: GitHub Advisory Database [GHSA-f5wc-c3c7-36mc](https://github.com/advisories/GHSA-f5wc-c3c7-36mc) / CVE-2026-39832, [GHSA-jppx-rxg9-jmrx](https://github.com/advisories/GHSA-jppx-rxg9-jmrx) / CVE-2026-39833, [GHSA-45gg-vh54-h5m9](https://github.com/advisories/GHSA-45gg-vh54-h5m9) / CVE-2026-39828, [GHSA-x527-x647-q7gg](https://github.com/advisories/GHSA-x527-x647-q7gg) / CVE-2026-46595, [GHSA-5cgq-3rg8-m6cv](https://github.com/advisories/GHSA-5cgq-3rg8-m6cv) / CVE-2026-42508, [GHSA-89gr-r52h-f8rx](https://github.com/advisories/GHSA-89gr-r52h-f8rx) / CVE-2026-39831, [GHSA-pjp5-fpmr-3349](https://github.com/advisories/GHSA-pjp5-fpmr-3349) / CVE-2026-48529, [GHSA-v2wp-frmc-5q3v](https://github.com/advisories/GHSA-v2wp-frmc-5q3v) / CVE-2026-55166, [GHSA-r9gp-7f88-9r54](https://github.com/advisories/GHSA-r9gp-7f88-9r54) / CVE-2026-55165, [GHSA-x3vf-mgxj-7785](https://github.com/advisories/GHSA-x3vf-mgxj-7785) / CVE-2026-55163, [GHSA-54vg-pfh7-jq95](https://github.com/advisories/GHSA-54vg-pfh7-jq95) / CVE-2026-55162, and [GHSA-xcjm-wqff-m669](https://github.com/advisories/GHSA-xcjm-wqff-m669) / CVE-2026-49219.

July 8 update: GitHub Advisory Database added adjacent Go `x/crypto/ssh` boundary advisories [GHSA-w879-237q-wc7r](https://github.com/advisories/GHSA-w879-237q-wc7r) / CVE-2026-39829 for pathological RSA/DSA public-key parameters during unauthenticated public-key auth and [GHSA-vgwf-h737-ff37](https://github.com/advisories/GHSA-vgwf-h737-ff37) / CVE-2026-39830 for unsolicited global request responses blocking SSH connection reads.

These items are durable for operators because they expose reusable boundaries: agent checkpoint stores crossing into runtime deserialization, SDK identifiers crossing into URL paths, shared job-result storage crossing into pickle loading, SSH-agent constraints and callback permissions crossing into forwarded key use, source-address bypass, revoked-CA acceptance, hardware-key presence checks, MCP HTTP singletons crossing user-token boundaries, empty authorization requirements turning into allow-all certificate control-plane access, certificate URLs crossing into server-side fetches, user-controlled forwarding headers crossing into trusted client IPs, image-processing symlinks crossing policy-confined file reads, and appliance HTTP inputs crossing into SSRF/file-write or deserialization RCE paths.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-fjqc-hq36-qh5p](https://github.com/advisories/GHSA-fjqc-hq36-qh5p) / CVE-2026-48775 | `langgraph-checkpoint` default `JsonPlusSerializer` | checkpoint bytes at rest can be reconstructed as Python objects when workers resume state | Treat checkpoint stores as code-adjacent control planes; test only with disposable checkpointers and inert deserialization canaries. |
| [GHSA-w39p-vh2g-g8g5](https://github.com/advisories/GHSA-w39p-vh2g-g8g5) / CVE-2026-48776 | `langgraph-sdk` resource identifiers | caller-supplied IDs are interpolated into URL templates without format enforcement | Hunt for SDK callers that pass end-user IDs into resource methods while upstream auth is path-prefix based. |
| [GHSA-g697-2xrc-gc46](https://github.com/advisories/GHSA-g697-2xrc-gc46) / CVE-2026-9291 | Amazon Braket SDK `job.result()`, `load_job_result()`, and `load_job_checkpoint()` | S3 job-result metadata can select `pickled_v4`, causing `pickle.loads()` on result values | Validate ML/quantum job output buckets as execution-adjacent supply-chain stores, using marker-only results. |
| [GHSA-qcqw-jwxc-2hqg](https://github.com/advisories/GHSA-qcqw-jwxc-2hqg) / CVE-2026-48508 | Lemur `StrictRolePermission` / `AuthorityCreatorPermission` | unset flags created Flask-Principal permissions with zero `Need`s, and empty needs allow every authenticated identity | Test certificate-manager endpoints for **auth-present but role-requirement-empty** behavior with read-only users. |
| [GHSA-f5wc-c3c7-36mc](https://github.com/advisories/GHSA-f5wc-c3c7-36mc) / CVE-2026-39832, [GHSA-jppx-rxg9-jmrx](https://github.com/advisories/GHSA-jppx-rxg9-jmrx) / CVE-2026-39833 | Go `x/crypto/ssh/agent` | destination and confirm-before-use constraints can be stripped, ignored, or accepted without enforcement by in-memory/forwarded agents | Audit agent-forwarding trust chains where a constrained key is expected to remain constrained on a remote hop. |
| [GHSA-45gg-vh54-h5m9](https://github.com/advisories/GHSA-45gg-vh54-h5m9) / CVE-2026-39828 | Go `x/crypto/ssh` server callbacks | `PartialSuccessError` with permissions can drop certificate restrictions such as `force-command` after a second factor | Test SSH certificate restrictions across multi-factor authentication transitions, not only on first-factor success. |
| [GHSA-x527-x647-q7gg](https://github.com/advisories/GHSA-x527-x647-q7gg) / CVE-2026-46595 | Go `x/crypto/ssh` `VerifiedPublicKeyCallback` | callback mixes can skip source-address validation when non-public-key callbacks are present | Verify source-address restrictions across every accepted authentication callback path, especially MFA or keyboard-interactive fallbacks. |
| [GHSA-5cgq-3rg8-m6cv](https://github.com/advisories/GHSA-5cgq-3rg8-m6cv) / CVE-2026-42508 | Go `x/crypto/ssh/knownhosts` | revoked CA `SignatureKey` status can be missed when validating host certificates | Treat `@revoked` known-hosts entries as active auth controls and test host-certificate chains against revoked CA markers. |
| [GHSA-89gr-r52h-f8rx](https://github.com/advisories/GHSA-89gr-r52h-f8rx) / CVE-2026-39831 | Go `x/crypto/ssh` FIDO/U2F key verification | security-key signatures can be accepted without checking the User Presence flag | Validate whether hardware-key policies really require touch, or whether a server/library path accepts no-touch signatures. |
| [GHSA-w879-237q-wc7r](https://github.com/advisories/GHSA-w879-237q-wc7r) / CVE-2026-39829 | Go `x/crypto/ssh` public-key parsing | oversized RSA moduli or DSA parameters can consume minutes of CPU during unauthenticated public-key verification | Use local harnesses or tightly scoped lab connections to test SSH auth parser resilience before exposing custom Go SSH services. |
| [GHSA-vgwf-h737-ff37](https://github.com/advisories/GHSA-vgwf-h737-ff37) / CVE-2026-39830 | Go `x/crypto/ssh` connection state | unsolicited global request responses can fill an internal buffer and block connection read loops | Treat peer-message handling as an SSH service robustness boundary; prove with one-connection lab harnesses, not broad network DoS. |
| [GHSA-pjp5-fpmr-3349](https://github.com/advisories/GHSA-pjp5-fpmr-3349) / CVE-2026-48529 | GitHub MCP Server HTTP lockdown mode | process-global repo-access cache can reuse the first request's GraphQL client for later users | Test multi-user MCP HTTP deployments for token and repo-scope confusion with two disposable GitHub accounts/repos. |
| [GHSA-v2wp-frmc-5q3v](https://github.com/advisories/GHSA-v2wp-frmc-5q3v) / CVE-2026-55166 | Lemur ACME and certificate ownership flows | SSO auto-provisioned users can combine ACME URL SSRF with creator-equality authorization drift | Treat certificate automation URLs and creator IDs as PKI control-plane inputs; prove only with owned callbacks and synthetic certs. |
| [GHSA-r9gp-7f88-9r54](https://github.com/advisories/GHSA-r9gp-7f88-9r54) / CVE-2026-55165 | Lemur JWT verifier | token verification follows attacker-supplied algorithm metadata in chain-dependent scenarios | Include JWT algorithm-confusion decision tables when a separate secret/key disclosure exists; do not claim single-request takeover without that precondition. |
| [GHSA-x3vf-mgxj-7785](https://github.com/advisories/GHSA-x3vf-mgxj-7785) / CVE-2026-55163 | Lemur role update API | role members can rewrite membership via `PUT /api/1/roles/<id>` while delete is admin-gated | Use two-role lab users to check whether membership edit endpoints require admin or merely existing membership. |
| [GHSA-54vg-pfh7-jq95](https://github.com/advisories/GHSA-54vg-pfh7-jq95) / CVE-2026-55162 | Lemur certificate verification | CRL Distribution Point and OCSP URLs inside uploaded certificates are fetched without destination filtering | Test certificate-upload SSRF with synthetic certificates and owned callbacks only. |
| [GHSA-3fxj-6jh8-hvhx](https://github.com/advisories/GHSA-3fxj-6jh8-hvhx), [GHSA-rjr7-jggh-pgcp](https://github.com/advisories/GHSA-rjr7-jggh-pgcp), [GHSA-9g5q-2w5x-hmxf](https://github.com/advisories/GHSA-9g5q-2w5x-hmxf) | `go-chi/chi` `middleware.RealIP` | `True-Client-IP`, `X-Real-IP`, or leftmost `X-Forwarded-For` can replace `r.RemoteAddr` without trusted-proxy validation | Check IP ACLs, rate limits, audit attribution, and admin route gates that trust framework-derived client IPs. |
| [GHSA-xcjm-wqff-m669](https://github.com/advisories/GHSA-xcjm-wqff-m669) / CVE-2026-49219 | ImageMagick policy enforcement | filename parsing around symlinks can bypass a configured security policy and read a disallowed file | Validate image-processing sandboxes with disposable symlink canaries, not real secrets or host files. |
| [CVE-2026-20230](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Cisco Unified Communications Manager / SME | crafted unauthenticated HTTP requests can trigger SSRF through the appliance and write files for later root escalation | Scope perimeter UC appliances for route-level SSRF validation with owned callbacks and no production file writes. |
| [CVE-2026-12569](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | PTC Windchill PDMLink / FlexPLM | untrusted deserialization exposed as critical remote code execution in product lifecycle systems | Prioritize version and exposure confirmation, then reproduce only in approved labs with non-executing deserialization canaries. |

## Operator triage

1. **Storage write is often runtime control.** Checkpoint stores, job-result buckets, and model/workflow artifacts should be treated as inputs to future code paths, not passive data.
2. **Identifier validation belongs before SDK calls.** UUID-looking fields, run IDs, thread IDs, checkpoint IDs, and resource IDs should reject `/`, `%2f`, `..`, `?`, `#`, encoded separators, and mixed-normalization variants before reaching URL-building helpers.
3. **Empty role lists are authorization decisions.** Look for wrappers where feature flags decide which roles to require; if the disabled branch constructs a permission object with no requirements, verify whether the framework treats it as allow-all.
4. **SSH constraints must survive handoffs.** Confirm that destination restrictions, confirmation prompts, `force-command`, source-address, revoked-CA markers, user-presence flags, and critical options still apply after agent forwarding, in-memory keyring import, callback changes, and MFA partial-success flows.
5. **MCP HTTP servers are multi-user web apps.** A per-process cache or singleton that stores a request-scoped GraphQL/API client can turn the first user's token into everyone else's policy oracle.
6. **PKI automation is a control plane.** ACME directory URLs, CRL/OCSP endpoints, certificate owner fields, JWT verifier metadata, and role membership APIs can all become privilege or SSRF pivots.
7. **Forwarded IP headers are hostile unless a trusted proxy boundary is enforced.** If the app is directly reachable, client-supplied `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` should not influence route gates or throttles.
8. **Image processors need file-boundary canaries.** Policy files that block `@/path`, delegates, or sensitive directories should also be tested through symlink and filename-normalization paths.
9. **Appliance KEVs need product ownership first.** For Cisco Unified CM and Windchill/FlexPLM, collect version, exposed route, and role/reachability evidence before any SSRF or deserialization proof.

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

### SSH-agent and SSH-certificate constraint harness

- Preconditions: owned SSH lab, disposable keys, a mock or throwaway remote host, and no production bastions, user keys, or agent sockets.
- Add a constrained key to the agent with destination or confirm-before-use expectations, then forward it through the same client/library path used by the target product.
- Attempt only harmless signing or login decisions that prove whether the remote side can use the key outside the intended destination or without the expected confirmation gate.
- For server-side certificate restrictions, test multi-factor flows where the first factor returns partial success and later factors complete authentication. Confirm whether `force-command`, source-address, principal, and extension restrictions remain attached.
- Exercise every configured authentication callback combination. A source-address restriction that holds for public-key-only login may fail when keyboard-interactive, password, or MFA callbacks participate in the same flow.
- For known-hosts validation, create a lab CA, sign a disposable host key, then mark the CA or signature key as `@revoked` in a temporary known-hosts file. Confirm whether the client rejects the host certificate before any real connection is trusted.
- For FIDO/U2F security keys, use a lab key or simulator and record whether the server accepts a signature when the User Presence bit is unset. Do not test with production hardware tokens or operator accounts.
- Evidence should include library version, key constraints, agent-forwarding path, remote signing/auth decision, and a patched-version negative control. Do not use real operator keys or persist agent sockets on shared hosts.

### Go SSH parser and peer-message harness

- Preconditions: explicit authorization, an isolated Go SSH server/client harness or staging endpoint, disposable keys, and agreed resource limits.
- For public-key parser checks, feed synthetic RSA/DSA public keys with bounded parameter-size variants into the exact authentication path. Prefer unit/integration harnesses that time signature verification locally before any network proof.
- For unsolicited global request responses, use a lab peer that sends a small, controlled sequence and records whether the Go connection read loop cleans up or blocks. Keep it to one connection unless the program explicitly authorizes resilience testing.
- Evidence should include `golang.org/x/crypto` version, key/message corpus description, elapsed time or goroutine/connection cleanup observation, and a patched-version negative control.
- Do not run unauthenticated CPU or connection-exhaustion tests against shared bastions, production Git endpoints, CI runners, or appliance SSH services.

### GitHub MCP HTTP lockdown cache harness

- Preconditions: lab GitHub MCP Server in HTTP mode, `--lockdown-mode` enabled, two disposable users or tokens, and two repos with intentionally different access.
- Start with user A and query only a canary repo/scope that user A can access. Then send user B's request through the same server process for a repo that should be denied or decided with B's token.
- Record whether lockdown-related GraphQL queries are made with user A's token after user B authenticates. Use mock repositories, redacted request IDs, and route-level decisions; never query private production repos or collect real token values.
- Evidence should include server mode, request ordering, token ownership labels, expected vs observed repo-access decision, and a fixed-version or per-request-cache negative control.

### Lemur ACME, certificate verification, JWT, and role-edit harness

- Preconditions: lab Lemur instance, SSO test users, disposable roles/certificates, fake JWT signing material, and owned callback infrastructure.
- For ACME and certificate verification SSRF, use only owned callback URLs embedded in `acme_url`, CRL Distribution Point, or OCSP fields. Record route, authenticated role, outbound callback, and any authorization check that should have blocked the request.
- For creator-equality and role-edit checks, create two lab users and roles. Prove only whether a non-admin can take over synthetic certificate ownership or rewrite a disposable role membership list.
- For JWT algorithm handling, build a decision table from the verifier configuration and a fake token corpus. Only demonstrate account takeover if a separate, authorized lab disclosure of the signing secret/key is part of scope.
- Never target metadata services, Kubernetes APIs, real CAs, production JWT secrets, or live certificate inventories.

### ImageMagick policy symlink harness

- Preconditions: isolated image-processing worker, explicit scope, a policy that denies a synthetic path, and a disposable directory tree.
- Create a marker file outside the allowed image directory and a symlink or filename-normalization variant inside the processing directory that references it.
- Run the same ImageMagick command path the application uses and confirm whether policy blocks the read before any output exposes marker content.
- Evidence should include ImageMagick version, policy excerpt, input filename/symlink layout, blocked-vs-read outcome, and fixed-version negative control.
- Do not point canaries at `/etc/passwd`, cloud credentials, application secrets, user uploads, or host paths outside the disposable lab.

### chi RealIP trust-boundary harness

- Preconditions: owned app or lab service using `go-chi/chi` `middleware.RealIP`, plus a harmless route whose behavior depends on client IP.
- Send paired requests with and without forged `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` headers. Include a direct-to-origin test and, if applicable, a test through the real trusted proxy.
- Validate effects on IP ACLs, rate limits, logs, and any admin/debug route gate. Keep target routes harmless and avoid bypassing real customer controls.
- Evidence should include network path, proxy headers, observed `RemoteAddr`, route decision, and a trusted-proxy-aware negative control.

### Appliance KEV validation boundaries

- Cisco Unified CM / SME: prove only route reachability and SSRF callback behavior in approved environments. Use owned callback domains and synthetic markers; do not write files to production appliances or chain to root escalation.
- PTC Windchill / FlexPLM: confirm affected product/version and deserialization exposure. Any payload testing belongs in a vendor lab or customer-approved clone with inert canaries only; do not run public RCE payloads or touch production PLM data.

## Reporting notes

- Lead with the boundary: **checkpoint store to worker deserialization**, **resource ID to URL path**, **job-result bucket to pickle load**, **SSH-agent constraints to remote key use**, **SSH callback permissions to source-address bypass**, **known-hosts revocation to host-certificate trust**, **hardware-key presence flag to unattended auth**, **MCP request token to process-global cache**, **empty permission needs to allow-all**, **certificate URL to SSRF**, **role membership to role rewrite**, **forwarded header to trusted IP**, **image symlink to policy-bypassed file read**, **appliance HTTP input to SSRF/file-write**, or **PLM deserialization to RCE**.
- Include exact package/product versions, route or method name, caller role, canary value, and negative controls.
- Keep all artifacts synthetic: disposable checkpoints, marker job results, throwaway SSH keys, read-only lab users, fake certificates, owned callbacks, symlinked marker files, and harmless route canaries.
