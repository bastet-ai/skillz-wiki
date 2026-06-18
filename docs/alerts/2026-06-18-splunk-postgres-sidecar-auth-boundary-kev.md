# Splunk PostgreSQL sidecar authentication-boundary validation

Source: hourly offensive-security scan, 2026-06-18. Primary entries: CISA KEV [CVE-2026-20253](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and Splunk advisory [SVD-2026-0603](https://advisory.splunk.com/advisories/SVD-2026-0603).

This KEV is durable for operators because it is not just a patch note: it exposes a reusable control-plane pattern where an appliance/application sidecar service is network-reachable through Splunk Enterprise and can perform file operations without the authentication expected on the main management plane. Treat it as a boundary-validation workflow for Splunk estates and similar products that embed auxiliary services.

## What changed

| Item | Confirmed detail | Operator value |
| --- | --- | --- |
| CVE-2026-20253 | Splunk Enterprise 10.2.0 through 10.2.3 and 10.0.0 through 10.0.6 could allow an unauthenticated network-reachable user to create or truncate arbitrary files through a PostgreSQL sidecar service endpoint. Splunk Enterprise 9.4 and earlier are listed as not affected; Splunk Cloud is listed as not affected. | Add sidecar endpoint reachability and unauthenticated file-operation boundaries to Splunk perimeter and internal management-plane assessments. |
| SVD-2026-0603 | The vulnerable component is reported as `splunkd`, with PostgreSQL sidecar functionality tied to Edge Processor, OpAmp, and SPL2 data pipelines. | Inventory sidecar-enabled deployments separately from ordinary search/index/dashboard exposure. |
| CISA KEV addition | CISA added the issue on 2026-06-18 as known exploited. | Prioritize exposure validation and evidence capture for internet-facing or broadly reachable Splunk management paths, but keep proofs non-destructive. |

## Scope and prerequisites

Validate only in an owned lab or under explicit customer authorization.

Required inputs:

- Confirmed Splunk Enterprise ownership and approved target list.
- Version evidence for Splunk Enterprise 10.0.x or 10.2.x instances.
- Network vantage point matching the assessment goal: internet edge, VPN user, internal workstation, or management subnet.
- Confirmation whether Edge Processor, OpAmp, or SPL2 data pipelines are in use before recommending any operational changes.

Do not test against Splunk Cloud for this CVE unless a separate customer-specific reason exists; Splunk's advisory says Splunk Cloud is not affected because PostgreSQL sidecars are not used there.

## Recon workflow

1. **Identify Splunk surfaces.** Start with known CMDB entries, certificate names, reverse-proxy routes, VPN-only management hostnames, and common Splunk ports such as web UI and management endpoints. Keep active probing inside the authorized scope.
2. **Separate user UI from sidecar/control-plane paths.** Record whether the deployment exposes only the normal authenticated web UI, a reverse-proxied management route, or additional sidecar-related routes. The operator question is whether lower-trust network clients can reach an endpoint that performs server-side file operations.
3. **Collect version evidence safely.** Prefer already-authorized administrative inventory, banner metadata, package manifests, or owner-provided version screenshots. If unauthenticated version routes are in scope, capture only product/version evidence.
4. **Map trust boundaries.** Document the caller network zone, reverse proxy, Splunk listener, sidecar endpoint, and filesystem effect boundary. Note whether authentication is enforced before any request reaches sidecar-backed behavior.

## Non-destructive validation boundaries

Use this as a proof design, not as an arbitrary-file-write recipe.

- **Reachability proof:** Show that a sidecar-related endpoint is reachable from a lower-trust network position where the Splunk owner expected authentication or segmentation. Evidence can be route status, authentication challenge behavior, proxy logs, or a denied/accepted request marker.
- **Authentication proof:** Compare the same harmless request unauthenticated, with a low-privilege user, and with an administrator. Positive evidence is a sidecar path that proceeds without the expected authentication gate.
- **File-operation proof in lab only:** If impact proof is approved, target only a disposable lab instance and only a pre-agreed canary path under a temporary directory created for the test. Record creation/truncation of that canary file and stop. Do not touch Splunk configuration, indexes, dispatch directories, app directories, credentials, logs, shell startup files, or service files.
- **Negative controls:** Repeat against a fixed version or a deployment with the PostgreSQL sidecar disabled where approved. Evidence should show the route is not reachable, authentication is required, or the canary operation is rejected.

## Evidence to capture

- Target ownership and approved scope reference.
- Splunk Enterprise version and whether it falls in 10.0.0-10.0.6 or 10.2.0-10.2.3.
- Network vantage point and route taken to the Splunk endpoint.
- Redacted request/response metadata showing the authentication decision, not exploit payloads.
- If lab file-operation proof is approved: canary file path, before/after metadata, and why the path was disposable.
- Negative control from a fixed, segmented, authenticated, or sidecar-disabled instance.

## Safety constraints

- Do not publish or reuse destructive arbitrary-file-write or truncation payloads.
- Do not attempt production file creation/truncation unless the customer has explicitly approved a disposable canary path and rollback plan.
- Do not read, overwrite, or truncate Splunk indexes, configs, credentials, app packages, dispatch artifacts, operating-system files, or logs.
- Do not scan unrelated Splunk instances discovered through shared hosting, cloud IP ranges, search engines, or certificate transparency unless they are in scope.
- Keep the report framed around the crossed boundary: **unauthenticated network client to Splunk sidecar file operation**.

## Reporting heuristic

A strong finding title is:

> Unauthenticated Splunk PostgreSQL sidecar endpoint can reach server-side file operations

Include the vulnerable version range, the reachable endpoint class, the expected authentication/segmentation control, the observed bypass, and a canary-only proof. Avoid claiming remote code execution or data theft unless the customer separately authorized and demonstrated a complete, non-synthetic chain.
