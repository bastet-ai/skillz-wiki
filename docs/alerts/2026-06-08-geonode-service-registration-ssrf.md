# GeoNode service-registration SSRF validation

Source: GitHub Security Advisories REST API, published/updated 2026-06-08.

This note is durable because GeoNode's advisory turns a product-specific SSRF into a reusable **service-import and WMS registration validation pattern** for geospatial portals, CMS-style data platforms, and other applications that validate user-supplied upstream service URLs. Use it only in authorized labs, staging systems, or explicitly scoped assessments.

## What changed

- **GeoNode service registration SSRF** — [GHSA-hw9r-6m78-w6h3](https://github.com/advisories/GHSA-hw9r-6m78-w6h3) / CVE-2026-39922: GeoNode versions `>= 4.0.0, < 4.4.5` and `>= 5.0.0, < 5.0.2` allow authenticated attackers to trigger outbound requests by submitting crafted service URLs during service-registration form validation.
- The advisory names the **WMS service handler** and calls out missing private-IP filtering or allowlist enforcement. Treat this as a pattern for any import/register/connect workflow that fetches a remote map, WMS/WFS, catalog, feed, webhook, or URL preview before persisting the configuration.
- [GHSA-v8f7-cg9p-w5jx](https://github.com/advisories/GHSA-v8f7-cg9p-w5jx) was updated as a withdrawn duplicate that points back to GHSA-hw9r-6m78-w6h3. Track the canonical GHSA/CVE in reports, but record the duplicate if a customer's dependency scanner surfaces it.

## Operator triage

1. Look for exposed GeoNode instances and adjacent geospatial portals in scope:
   - page titles, login panels, static paths, package metadata, container labels, or repository manifests mentioning `GeoNode`, `geonode`, WMS, WFS, CSW, OGC, GeoServer, MapStore, map layer registration, or service catalog import;
   - Python package ranges `geonode>=4.0.0,<4.4.5` and `geonode>=5.0.0,<5.0.2`.
2. Prioritize targets where a low-privileged authenticated user can reach service registration, data import, layer creation, catalog connection, or remote-service validation screens.
3. Treat validation-time callbacks as evidence even if the application rejects or never saves the submitted service. SSRF often happens during preview, validation, metadata discovery, or capability parsing.
4. Do not test cloud metadata, loopback admin panels, or third-party hosts unless the assessment scope explicitly permits it. A lab-owned HTTP/DNS listener is enough to prove the backend fetch primitive.

## Replayable validation boundary

### Service URL callback canary

1. Confirm authorization and create or use the lowest-privileged role that can access service registration or remote WMS/WFS/catalog import.
2. Start a lab-owned HTTP/DNS listener reachable by the target, such as an approved collaborator endpoint or an assessment-controlled VPS. Use a unique token in the hostname or path for each target and user role.
3. Submit the listener URL through the suspected service URL field. Prefer harmless schemes and normal web ports first:
   - `https://<token>.<listener-domain>/wms?service=WMS&request=GetCapabilities`
   - `http://<listener-host>:<approved-port>/geonode-ssrf/<token>`
4. If scope permits parser-boundary testing, vary only one dimension at a time: scheme, host representation, port, path, redirect behavior, and WMS capability parameters. Keep payloads inert and avoid sensitive destinations.
5. Vulnerable result: the listener receives a request from the application server or an intermediary controlled by the application, or the application response/logs prove that the backend attempted to fetch the supplied service URL.
6. Capture endpoint, HTTP method, parameter name, user role, GeoNode/package version, listener timestamp, source IP/user agent, and whether the request happened during validation, preview, or save.

## Recon and report heuristics

- Frame the finding as **authenticated service-registration URL validation reaches backend fetch** rather than generic SSRF. Strong evidence identifies the user role needed to trigger it and the exact validation step that causes egress.
- In geospatial apps, include WMS/WFS/OGC terminology in route and UI searches. SSRF sinks often hide behind "GetCapabilities", "register service", "remote layer", "catalog", or "harvest" workflows rather than obvious URL-preview features.
- For bug-bounty reports, show a benign callback proof first, then explain what internal-address classes the advisory says were not filtered. Do not claim metadata theft or internal port scanning unless those actions were explicitly authorized and demonstrated.
- If a scanner reports GHSA-v8f7-cg9p-w5jx, note that it is a duplicate/withdrawn advisory and map it to [GHSA-hw9r-6m78-w6h3](https://github.com/advisories/GHSA-hw9r-6m78-w6h3) / CVE-2026-39922 to avoid duplicate submissions.

## Sources

- GitHub Advisory Database: [GHSA-hw9r-6m78-w6h3 / CVE-2026-39922](https://github.com/advisories/GHSA-hw9r-6m78-w6h3)
- Duplicate GitHub advisory: [GHSA-v8f7-cg9p-w5jx](https://github.com/advisories/GHSA-v8f7-cg9p-w5jx)
- GeoNode release 4.4.5: <https://github.com/GeoNode/geonode/releases/tag/4.4.5>
- GeoNode release 5.0.2: <https://github.com/GeoNode/geonode/releases/tag/5.0.2>
- PyPA advisory database entry: <https://github.com/pypa/advisory-database/tree/main/vulns/geonode/PYSEC-2026-61.yaml>
- VulnCheck advisory: <https://www.vulncheck.com/advisories/geonode-ssrf-via-service-registration>
