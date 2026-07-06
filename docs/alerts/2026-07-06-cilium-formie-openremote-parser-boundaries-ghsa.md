# Cilium Envoy socket, Formie hidden-field SSTI, OpenRemote datapoint, and Open Babel parser-boundary checks

Source: hourly offensive-security scan, 2026-07-06. Primary entries: GitHub Advisory Database [GHSA-3fcv-jvfp-m4q9](https://github.com/advisories/GHSA-3fcv-jvfp-m4q9) / CVE-2026-49445, [GHSA-565m-g33j-jq96](https://github.com/advisories/GHSA-565m-g33j-jq96) / CVE-2026-52889, [GHSA-xj53-j257-hxvg](https://github.com/advisories/GHSA-xj53-j257-hxvg) / CVE-2026-49439, and [GHSA-55f6-pf8r-c2f4](https://github.com/advisories/GHSA-55f6-pf8r-c2f4) / CVE-2022-46292.

These advisories are durable for operators because each exposes a reusable boundary to test during authorized reviews: pod-local access to infrastructure admin sockets, request metadata rendered as server-side templates, read-only asset permissions reaching a write endpoint, and untrusted scientific file formats crossing into native parsers. Keep proofs synthetic: route/socket reachability, fixed canary strings, disposable asset datapoints, and local sanitizer traces only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-3fcv-jvfp-m4q9](https://github.com/advisories/GHSA-3fcv-jvfp-m4q9) / CVE-2026-49445 | Cilium L7 Envoy, embedded and standalone deployment models | Cilium L7 functionality could create a world-accessible Envoy admin socket on cluster nodes | Kubernetes assessments should check whether low-privilege pod or node-local users can reach service-mesh or CNI admin sockets that expose TLS material, routing state, or traffic-control operations. |
| [GHSA-565m-g33j-jq96](https://github.com/advisories/GHSA-565m-g33j-jq96) / CVE-2026-52889 | Verbb Formie for Craft 5, Hidden field defaults | request-derived Hidden field defaults, including User-Agent, Referer, current URL, query parameter, or cookie value, were copied into a value later rendered by Craft Twig | Public forms are worth testing when administrators configure hidden fields from request metadata. The bug-hunting pattern is request metadata crossing into server-side template evaluation. |
| [GHSA-xj53-j257-hxvg](https://github.com/advisories/GHSA-xj53-j257-hxvg) / CVE-2026-49439 | OpenRemote predicted datapoints API | endpoint accepted predicted datapoint writes from users with `read:assets` but without `write:assets` | API authorization reviews should include semantically writable subresources even when route names look analytical, predicted, cache-like, or derived. |
| [GHSA-55f6-pf8r-c2f4](https://github.com/advisories/GHSA-55f6-pf8r-c2f4) / CVE-2022-46292 | Open Babel MOPAC output reader | crafted `UNIT CELL TRANSLATION` blocks could write past a fixed `translationVectors[]` array when parsed by `obabel`, `OBConversion`, or bindings | File-ingestion reviews for chemistry, bioinformatics, and ML pipelines should treat scientific conversion utilities as native parser attack surface. Proofs belong in disposable, instrumented labs. |

## Operator triage

Prioritize targets where one of these conditions exists:

1. **Kubernetes node or pod-local code execution is in scope.** Cilium Envoy socket reachability matters when a workload, debug pod, daemonset, or low-privilege node user can touch CNI/service-mesh admin interfaces that were assumed private.
2. **Public Craft/Formie forms use dynamic Hidden defaults.** The interesting cases are request-controlled fields rendered server-side: User-Agent, Referer, current URL, query parameter, or cookie value.
3. **OpenRemote tenants expose read-only asset roles.** Test whether read-only principals can mutate predicted, cached, derived, or forecast data tied to assets.
4. **Applications parse user-supplied chemistry files.** Open Babel is often embedded behind upload converters, molecule previewers, notebook workflows, search indexing, or ETL jobs.
5. **The impact crosses a real trust boundary.** A route that returns only a canary, a disposable predicted datapoint, or a local sanitizer crash is evidence; production secret reads, traffic disruption, or destructive parser payloads are not acceptable wiki proof artifacts.

## Replayable validation boundaries

### Cilium Envoy admin-socket exposure check

Use this only in an owned cluster or an engagement where Kubernetes node/pod-local testing is explicitly authorized.

- Preconditions: affected Cilium version range, L7 policy or functionality enabled, a disposable namespace or lab node, and a low-privilege test identity matching the threat model.
- From the test context, enumerate only socket presence and permission metadata for Cilium/Envoy admin sockets. Capture path, owner, mode, and whether a harmless read-only admin endpoint is reachable.
- Positive evidence: the low-privilege context can connect to the Envoy admin socket that should be confined to Cilium/Envoy control processes.
- Negative controls: patched Cilium version, cluster without L7 Envoy enabled, and a context that should not have node-local socket access.
- Do not invoke disruptive admin operations, dump TLS secrets, terminate Envoy, alter routes, or capture live traffic. Report reachability and redacted endpoint metadata only.

### Formie request-derived Hidden default SSTI canary

Use this when a public Formie form contains a Hidden field whose default source is request-derived rather than an admin-authored custom template.

- Preconditions: authorized Craft/Formie target or local reproduction, affected `verbb/formie` version, public form with an affected Hidden default source, and an inert canary string.
- Send a request where the selected metadata source carries harmless template syntax that evaluates to a fixed marker, not code execution or secret access.
- Render or submit the form through the normal front-end path and capture whether the response or submitted field value contains the evaluated marker rather than the literal input.
- Positive evidence: request-controlled metadata is evaluated by server-side Twig during Hidden field rendering.
- Negative controls: patched Formie `3.1.27` or later, a Hidden field using a static literal default, and a custom admin-authored default where template rendering is expected.
- Do not attempt RCE, read Craft config, enumerate environment variables, or inject persistent payloads into production forms.

### OpenRemote predicted-datapoint write authorization check

Use this for API authorization reviews where synthetic assets and test users are available.

- Preconditions: disposable OpenRemote realm or tenant, one synthetic asset, one attribute such as `temperature`, and a test principal with `read:assets` but not `write:assets`.
- Confirm the same principal cannot update the asset through normal asset-write APIs.
- Attempt to write a predicted datapoint with a harmless marker value to the predicted-datapoint route for the synthetic asset.
- Positive evidence: the API accepts the write and later reads or database evidence show only the synthetic predicted datapoint changed.
- Negative controls: patched build, a principal with no asset permissions, and a legitimate writer role to prove the route itself works.
- Do not alter production telemetry, commands, setpoints, billing data, or operational assets. Keep marker values obviously synthetic.

### Open Babel native-parser ingestion harness

Use this only in a local lab or an explicitly authorized file-ingestion test harness.

- Preconditions: affected Open Babel build, ASAN/UBSAN or equivalent instrumentation where practical, and disposable input/output directories.
- Prefer the upstream minimized regression sample or a vendor-supplied proof file over crafting new payloads.
- Run the parser/converter in a sandboxed process with strict CPU, memory, and filesystem limits. Capture version, command line, sanitizer trace, and patched-version negative control.
- Positive evidence: an affected build trips the `UNIT CELL TRANSLATION` parser issue while patched Open Babel `3.2.0` or later does not.
- Keep proofs local. Do not upload crash files to third-party production converters, shared notebooks, customer ETL jobs, or public molecule previewers.

## Reporting notes

- Lead with the crossed boundary: **pod-local user to Envoy admin socket**, **request metadata to server-side Twig**, **read-only asset role to predicted datapoint write**, or **untrusted scientific file to native parser memory corruption**.
- Include version, feature/configuration preconditions, test identity, exact synthetic canary, positive/negative decision table, and patched or fixed-control evidence.
- Keep impact claims scoped to what was proven. Do not claim cluster compromise, RCE, telemetry manipulation, or arbitrary native code execution unless the authorized test safely demonstrates that chain in a lab.

## July 6 OpenRemote KNX import and realm-boundary follow-up

Later July 6 GitHub Advisory Database entries add two adjacent OpenRemote checks: [GHSA-7v6w-c3f4-9wpq](https://github.com/advisories/GHSA-7v6w-c3f4-9wpq) / CVE-2026-54640 for an incomplete XXE fix in the KNX asset import path, and [GHSA-xqr9-4wvv-gvch](https://github.com/advisories/GHSA-xqr9-4wvv-gvch) / CVE-2026-54641 for cross-realm user information disclosure in `UserResourceImpl`.

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-7v6w-c3f4-9wpq](https://github.com/advisories/GHSA-7v6w-c3f4-9wpq) | OpenRemote KNX ETS project ZIP import | a sibling asset-import handler missed the XXE protections added to the Velbus parser path | Incomplete-fix reviews should diff sibling import handlers and prove file-read reachability with synthetic mounted canary files only. |
| [GHSA-xqr9-4wvv-gvch](https://github.com/advisories/GHSA-xqr9-4wvv-gvch) | OpenRemote realm user API | tenant realm admins could supply user UUIDs from other realms and receive profile/role data | Multi-tenant API tests should pair route role checks with object-realm ownership checks, especially for identity-provider wrapper routes. |

### OpenRemote KNX XXE and realm-ownership harness

- Preconditions: disposable OpenRemote lab with two synthetic realms, non-sensitive test users, an affected KNX import path, one mounted canary text file outside application secrets, and no production telemetry or identity data.
- For KNX import, build a minimal ETS project ZIP that references only the synthetic canary file through an XML external entity. Positive evidence is the canary marker appearing in import output, logs, or controlled error text. Do not target `/etc/passwd`, cloud credentials, application config, or service-account files.
- For realm ownership, authenticate as a realm admin in tenant B and request only synthetic tenant A user IDs through the affected profile/role routes. Positive evidence is a route decision table showing tenant B can read tenant A canary user metadata despite lacking cross-realm authority.
- Negative controls: patched KNX parser path using the same secure XML factory as sibling handlers, external entities disabled in every XML/XSLT import path, explicit `targetUser.realm == caller.realm` checks, and patched builds that deny the same requests.
- Reporting should separate **authenticated file-read through import parser** from **cross-tenant identity metadata disclosure** and include only redacted/synthetic canary values.
