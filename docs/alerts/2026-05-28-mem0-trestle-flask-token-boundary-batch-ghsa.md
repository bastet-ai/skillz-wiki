# mem0, compliance-trestle, and Flask token-auth boundary batch (GHSA, 2026-05-28)

**Signal:** GitHub Advisory Database published a May 28 follow-on batch with reusable offensive-operator value across unauthenticated AI memory APIs, recursive template rendering, remote fetch SSRF, and empty-token authentication edge cases. The durable lesson is to test where automation treats data fields, fetch URLs, memory identifiers, or missing credentials as safe because the surrounding template, import workflow, or route is considered trusted.

Promoted items:

- `GHSA-jfv9-68m5-gjjr` / `CVE-2026-31240`: mem0 / `mem0ai <= 1.0.0` exposes memory management API endpoints such as `PUT /memories/{memory_id}` without authentication or authorization, allowing unauthenticated memory modification, overwrite, or deletion.
- `GHSA-gg2g-p7xc-qqmm` / `CVE-2026-46439`: compliance-trestle `trestle author jinja` recursively re-renders output, so attacker-controlled data fields inside otherwise trusted templates can become executable Jinja and reach command execution as the process user.
- `GHSA-w76h-q7c6-jpjp` / `CVE-2026-46380`: compliance-trestle remote fetching passes user-supplied HTTPS URLs into fetch logic without sufficient validation, creating SSRF paths from OSCAL / trestle workflows into internal services or metadata endpoints.
- `GHSA-p44q-vqpr-4xmg` / `CVE-2026-34531`: Flask-HTTPAuth `<= 4.8.0` can invoke token verification with an empty string when a token-protected route receives no token or an empty token; applications that store empty-string tokens can authenticate the request as that user.

Reviewed but not promoted standalone:

- `GHSA-7j6w-vvw2-5f9c` / `CVE-2026-46405`: OpenBao Kerberos auth can create inaccessible default-policy tokens on error paths, but the advisory states the caller does not receive the token and the main impact is storage accumulation, so it is not a durable offensive validation workflow for this wiki.

Use this only in authorized tests. Keep proofs minimal: use lab agent memories, inert marker strings, tester-controlled callback servers, non-sensitive local/internal endpoints, and disposable users with empty test tokens. Do not alter real agent state, hit cloud metadata in production, run shell payloads, or attempt credential access unless the engagement explicitly provides a safe harness.

## Operator checklist

### 1. mem0 unauthenticated memory update / overwrite boundary

Where to look:

- Exposed mem0 / `mem0ai <= 1.0.0` servers, demos, internal AI workbenches, and agent memory APIs.
- Routes that expose memory CRUD operations such as `POST /memories`, `PUT /memories/{memory_id}`, and `DELETE /memories/{memory_id}`.
- Agent workflows where memory contents later influence retrieval, tool choice, prompt context, or user-specific decisions.

Safe validation path:

1. Confirm product and version from package locks, container metadata, API docs, or deployment fingerprints.
2. Create a disposable canary memory through an authorized test path, or ask for a lab memory ID.
3. From an unauthenticated client, attempt a benign `PUT /memories/{memory_id}` that changes only the canary text to a fixed marker.
4. Verify whether later reads or agent retrieval show the modified marker.
5. If deletion must be tested, delete only a disposable canary record and capture before/after evidence.

Evidence to capture:

- Version/package evidence and exposed memory API route.
- Request showing absence of authentication headers or cookies.
- Canary memory ID, original marker, modified marker, and retrieval proof.
- Any downstream agent behavior change, described separately from the API write proof.

Reporting heuristic: strong reports prove **unauthenticated write or delete of another caller's memory record plus a downstream trust path where that memory affects retrieval, agent context, or user-visible state**.

### 2. compliance-trestle recursive Jinja SSTI from data fields

Where to look:

- CI jobs, documentation generators, compliance portals, or agent workflows running `trestle author jinja`.
- Versions `<= 3.12.1` and `>= 4.0.0, < 4.0.3`.
- Trusted templates that render untrusted SSP, OSCAL, lookup-table, repository, issue, or user-supplied fields.

Safe validation path:

1. Confirm the trestle version and identify who controls the template versus the rendered data.
2. In a disposable workspace, place a harmless Jinja expression marker in a data field that a trusted template renders as plain text.
3. Run the same `trestle author jinja` flow and verify whether the marker is evaluated on a later recursive render pass.
4. If command execution proof is required, use an isolated lab command that prints a fixed marker or writes inside `/tmp` under the test container; do not touch secrets, shells, profiles, hooks, or CI configuration.
5. Document whether attacker control reaches only data fields, because the notable boundary is that template control is not required.

Evidence to capture:

- Version and exact `trestle author jinja` invocation.
- Trusted template snippet and attacker-controlled data field, with payloads sanitized.
- Output proving second-pass evaluation of data-sourced template syntax.
- Process user / execution context if demonstrated in a lab.

Reporting heuristic: prioritize findings where **contributor-controlled compliance data flows into a trusted template and becomes executable during recursive rendering**, especially in CI or agent-run repositories.

### 3. compliance-trestle remote-fetch SSRF boundary

Where to look:

- OSCAL imports, remote cache workflows, and trestle automation that accepts contributor-controlled `https://` references.
- CI environments with network access to internal documentation, service discovery, artifact stores, or cloud metadata.
- Versions `>= 4.0.0, < 4.0.3` and `< 3.12.2`.

Safe validation path:

1. Confirm the trestle version and the remote-fetch command path.
2. Stand up a tester-owned HTTPS callback endpoint and reference it from the same OSCAL / remote-cache field the target workflow consumes.
3. Trigger the import or fetch in a lab or scoped CI run and verify callback receipt from the server-side environment.
4. If internal reachability must be shown, use a safe collaborator endpoint or pre-approved non-sensitive internal URL; do not query metadata IPs, admin panels, or secret stores in production.
5. Capture whether the response body is cached, logged, committed, or exposed to the requester.

Evidence to capture:

- Version, fetch field, and remote URL source under attacker control.
- Callback timestamp, source IP / runner identity, and user agent if available.
- Whether redirects, private IPs, or scheme variants are accepted, tested only against approved endpoints.
- Any cached output path or artifact exposure.

Reporting heuristic: the highest-signal reports show **untrusted OSCAL or project input causing server-side fetches from a more privileged network location**, with a clear artifact or callback proving origin.

### 4. Flask-HTTPAuth empty-token authentication boundary

Where to look:

- Flask apps using Flask-HTTPAuth token authentication with database-backed token lookup.
- User tables where users without assigned API tokens are stored as empty strings instead of `NULL`.
- Token-protected routes that return different data for authenticated users.

Safe validation path:

1. Confirm Flask-HTTPAuth `<= 4.8.0` from dependencies, response headers, lockfiles, or source review.
2. Identify whether token verification searches user records by raw token value.
3. In a lab or explicitly scoped account, create a disposable user whose token field is an empty string.
4. Request a token-protected route with no token and then with an empty token value, and compare the application identity / response against unauthenticated and valid-token controls.
5. Do not enumerate real users or abuse production routes; the proof should use a known disposable account.

Evidence to capture:

- Dependency version and token verification callback behavior.
- Database/source evidence that empty strings can exist as token values.
- HTTP requests for missing token, empty token, and negative/positive controls.
- Response showing the authenticated identity or protected data for the disposable empty-token user.

Reporting heuristic: strong reports prove the three-part chain: **affected Flask-HTTPAuth version, empty-string token stored for a user, and missing/empty token request authenticating as that user**. Without the empty-token data condition, this is usually configuration risk rather than exploitable impact.

## References

- [mem0 memory management authorization advisory (`GHSA-jfv9-68m5-gjjr`)](https://github.com/advisories/GHSA-jfv9-68m5-gjjr)
- [compliance-trestle recursive Jinja SSTI advisory (`GHSA-gg2g-p7xc-qqmm`)](https://github.com/advisories/GHSA-gg2g-p7xc-qqmm)
- [compliance-trestle remote-fetch SSRF advisory (`GHSA-w76h-q7c6-jpjp`)](https://github.com/advisories/GHSA-w76h-q7c6-jpjp)
- [Flask-HTTPAuth empty-token advisory (`GHSA-p44q-vqpr-4xmg`)](https://github.com/advisories/GHSA-p44q-vqpr-4xmg)
