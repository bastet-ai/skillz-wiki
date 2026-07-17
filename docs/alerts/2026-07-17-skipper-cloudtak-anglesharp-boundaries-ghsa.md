# Skipper, CloudTAK, and AngleSharp boundary checks

Sources: hourly offensive-security scan, 2026-07-17 GitHub Security Advisory updates. Primary entries: [GHSA-8qqm-fp2q-v734](https://github.com/advisories/GHSA-8qqm-fp2q-v734), [GHSA-5587-2x54-jj6h](https://github.com/advisories/GHSA-5587-2x54-jj6h), [GHSA-r95q-fp26-h3hc](https://github.com/advisories/GHSA-r95q-fp26-h3hc), and [GHSA-pgww-w46g-26qg](https://github.com/advisories/GHSA-pgww-w46g-26qg).

This batch is durable for operators because the advisories map to repeatable assessment surfaces: request-body policy enforcement that can fail open on truncation, unauthenticated in-cluster route topology services, authenticated full-read SSRF in map/GIS helper routes, and sanitizer parser differentials between server-side DOM libraries and browsers.

!!! warning "Authorized validation only"
    Use lab Skipper/OPA deployments, disposable Kubernetes namespaces, owned callback hosts, synthetic local services, and harmless HTML markers. Never query cloud metadata, enumerate production clusters, dump live route tables, read internal services, or deliver browser payloads to real users.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-8qqm-fp2q-v734](https://github.com/advisories/GHSA-8qqm-fp2q-v734) | Skipper `opaAuthorizeRequestWithBody` | A declared `Content-Length` larger than `maxBodyBytes` can make OPA receive an empty `parsed_body` while the full request body still reaches upstream | Test body-aware authorization for truncation markers and fail-open Rego shapes, not only small-body allow/deny cases. |
| [GHSA-5587-2x54-jj6h](https://github.com/advisories/GHSA-5587-2x54-jj6h) / CVE-2026-54246 | Skipper `routesrv` | Cluster-wide route, filter-chain, backend, Redis, and Valkey topology is served over HTTP with method checks but no authentication | From a namespace-scoped pod, validate whether route aggregation services expose cross-namespace topology outside Kubernetes RBAC. |
| [GHSA-r95q-fp26-h3hc](https://github.com/advisories/GHSA-r95q-fp26-h3hc) / CVE-2026-55177 | CloudTAK `/api/esri*` | Authenticated ESRI helper routes pass user-controlled `url`, `portal`, `server`, or `layer` values into server-side fetches without IP/DNS/host classification and return upstream JSON/error bodies | Treat map, GIS, basemap, and portal proxy helpers as full-read SSRF candidates, especially when path sniffing is confused with destination safety. |
| [GHSA-pgww-w46g-26qg](https://github.com/advisories/GHSA-pgww-w46g-26qg) / CVE-2026-54570 | AngleSharp HTML parser/formatter | MathML `annotation-xml encoding="text/html"` is not treated as an HTML integration point, and serialized attribute values may keep raw `<`/`>` characters | Test server-side sanitizers for parse/serialize/reparse mutation XSS where the sanitizer DOM differs from the browser DOM. |

## Replayable validation boundaries

### Skipper OPA body-truncation checks

1. Stand up Skipper and OPA in a lab with one route to a canary upstream that records status, method, path, and request body length.
2. Configure `opaAuthorizeRequestWithBody` with a small `maxBodyBytes` value and a deny-on-presence policy such as a harmless `action == "delete"` marker.
3. Send three controls: a small forbidden JSON body, an oversized forbidden JSON body with a declared `Content-Length`, and a small chunked forbidden body.
4. Positive evidence is a status split where small/chunked forbidden bodies are denied but the oversized declared body is allowed and reaches the upstream.
5. Capture the OPA input fields, especially whether body content is absent and whether a truncation indicator is available. Do not forward destructive verbs to real services.

Report this as **request body -> OPA parsed-body policy -> truncation/oversize fail-open -> upstream receives forbidden marker**. Include the configured size limit, body lengths, status table, and fixed-policy negative control that denies on truncated or missing body state.

### Skipper `routesrv` topology exposure checks

1. In an approved Kubernetes lab, deploy Skipper with `routesrv` and at least two synthetic namespaces/routes.
2. From a pod with intentionally minimal Kubernetes RBAC, attempt only HTTP `GET`/`HEAD` requests to the routesrv service name and port used in the deployment.
3. Check `/routes`, `/routes/{zone}`, `/swarm/redis/shards`, and `/swarm/valkey/shards` with canary-only route and cache names.
4. Positive evidence is cross-namespace route/filter/backend or cache-topology data returned to a pod that could not read those objects from the Kubernetes API.
5. Negative controls should show authentication, network policy, or service isolation blocking the same pod.

Report this as **namespace-limited workload -> unauthenticated route aggregation HTTP service -> cluster-wide topology**. Redact internal service names and use synthetic route labels in public evidence.

### CloudTAK ESRI full-read SSRF checks

1. Use a lab CloudTAK tenant and a disposable low-privileged authenticated user if the route only requires any valid token.
2. Host owned ESRI-like JSON canaries at an internet domain, a redirector, and a synthetic local lab service. Avoid metadata, loopback admin ports, or real internal services.
3. Exercise `POST /api/esri` with body `url` and `GET /api/esri/*` variants that accept `portal`, `server`, or `layer` parameters.
4. Include path-shape controls such as `/rest`, `/arcgis/rest`, and `/sharing/rest` to distinguish path sniffing from final destination validation.
5. Positive evidence is server-side callback traffic plus reflected JSON/error markers in the API response.

Report this as **authenticated map-helper URL -> server-side fetch -> full response reflected to caller**. Include callback logs, route names, parameter names, redirect/final-host decisions, and fixed guard behavior.

### AngleSharp sanitizer parser-differential checks

1. Build a local harness around the exact server-side sanitizer or HTML processing pipeline that uses AngleSharp; do not test against live user content.
2. Feed harmless markers inside MathML `annotation-xml encoding="text/html"` and RCDATA-like elements such as `title` or `style`.
3. Compare three views: elements seen by the sanitizer DOM, serialized HTML emitted by the pipeline, and a browser or browser-equivalent reparse of that serialized output.
4. Positive evidence is a marker element or attribute that is absent from the sanitizer DOM but appears after browser reparse.
5. Keep payloads inert: use `data-*` attributes, synthetic tags, or non-executing markers unless an approved lab explicitly authorizes executable XSS proof.

Report this as **server-side parser DOM -> sanitizer decision -> serialized HTML -> browser reparse mismatch**. Include sanitized inputs/outputs, DOM diff tables, library versions, and a fixed-version negative control.

## Operator checklist

- [ ] Did the proof use synthetic bodies, routes, services, and HTML markers only?
- [ ] Did body-policy testing include oversized declared `Content-Length`, chunked, and small-body controls?
- [ ] Did cluster topology evidence prove an RBAC boundary crossing without exposing real service names?
- [ ] Did SSRF validation stop at owned callbacks and synthetic local services?
- [ ] Did mXSS evidence compare sanitizer DOM, serialized output, and browser reparse behavior?
