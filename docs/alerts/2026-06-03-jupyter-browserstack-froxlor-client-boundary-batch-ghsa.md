# Jupyter Enterprise Gateway, browserstack-runner, Froxlor API, and client-redirect boundaries

**Sources:** [GHSA-f49j-v924-fx9w / CVE-2026-44181](https://github.com/advisories/GHSA-f49j-v924-fx9w), [GHSA-cfw7-6c5v-2wjq / CVE-2026-44182](https://github.com/advisories/GHSA-cfw7-6c5v-2wjq), [GHSA-chq7-94j8-cj28 / CVE-2026-44180](https://github.com/advisories/GHSA-chq7-94j8-cj28), [GHSA-6vr3-7wcx-v5g5 / CVE-2026-49143](https://github.com/advisories/GHSA-6vr3-7wcx-v5g5), [GHSA-8rpw-6cqh-2v9h / CVE-2026-49144](https://github.com/advisories/GHSA-8rpw-6cqh-2v9h), [GHSA-f9rx-7wf7-jr36](https://github.com/advisories/GHSA-f9rx-7wf7-jr36), [GHSA-hg6j-4rv6-33pg / CVE-2026-47265](https://github.com/advisories/GHSA-hg6j-4rv6-33pg), [GHSA-jmmv-h3mp-59v8 / CVE-2026-44023](https://github.com/advisories/GHSA-jmmv-h3mp-59v8)  
**Affected packages:** PyPI `jupyter_enterprise_gateway` `< 3.3.0`; npm `browserstack-runner` `<= 0.9.5`; Composer `froxlor/froxlor` `< 2.3.7`; PyPI `aiohttp` `< 3.14.0`; PyPI `docling-core` `>= 1.5.0, < 2.74.1`.  
**Operator value:** durable validation patterns for environment-to-template injection, exposed local test runners, API key scope/2FA drift, cross-origin redirect cookie leakage, and document-fetch filename/path containment.

## Why this matters

The June 3 GitHub Advisory batch contains several different products, but the reusable offensive lesson is consistent: developer, notebook, hosting-panel, HTTP-client, and document-conversion components often trust an internal boundary that operators can test directly during authorized reviews.

Prioritize environments where these components sit near credentials or infrastructure control:

- Jupyter Enterprise Gateway deployments that let users create kernels through an HTTP API and run Kubernetes-backed kernels.
- CI or developer hosts running `browserstack-runner`, especially when TCP/8888 or a custom test-server port is reachable from other hosts.
- Froxlor panels where API keys are allowed for customer or admin accounts that also advertise two-factor authentication.
- Python services that call attacker-controlled or semi-controlled URLs with per-request `aiohttp` cookies.
- Docling ingestion services that accept untrusted URLs and use remote filename metadata when caching or materializing fetched resources.

## Advisory-to-boundary map

| Boundary | Advisory | Affected surface | What to validate |
| --- | --- | --- | --- |
| Jinja2 SSTI in kernel env | [GHSA-f49j-v924-fx9w](https://github.com/advisories/GHSA-f49j-v924-fx9w) | Jupyter Enterprise Gateway Kubernetes manifests | Whether `KERNEL_*` values supplied to `/api/kernels` are rendered as templates instead of inert strings. |
| YAML manifest injection | [GHSA-cfw7-6c5v-2wjq](https://github.com/advisories/GHSA-cfw7-6c5v-2wjq) | Jupyter Enterprise Gateway Kubernetes launch templates | Whether env-controlled manifest values can add fields, duplicate keys, or introduce extra YAML documents. |
| Prohibited UID/GID bypass | [GHSA-chq7-94j8-cj28](https://github.com/advisories/GHSA-chq7-94j8-cj28) | Jupyter Enterprise Gateway `KERNEL_UID` / `KERNEL_GID` policy | Whether string-format variants such as whitespace-normalization edge cases bypass root UID/GID deny lists. |
| Exposed test-runner RCE | [GHSA-6vr3-7wcx-v5g5](https://github.com/advisories/GHSA-6vr3-7wcx-v5g5) | `browserstack-runner` `/_log` handler | Whether an unauthenticated test-server endpoint processes JSON log arguments through Node `vm`/`eval` paths. |
| Exposed test-runner file read | [GHSA-8rpw-6cqh-2v9h](https://github.com/advisories/GHSA-8rpw-6cqh-2v9h) | `browserstack-runner` default static-file handler | Whether traversal stays confined to the project directory when requested with raw `../` segments. |
| API key bypasses 2FA | [GHSA-f9rx-7wf7-jr36](https://github.com/advisories/GHSA-f9rx-7wf7-jr36) | Froxlor RPC/API authentication | Whether API key + secret access is accepted for accounts whose web login requires a TOTP challenge. |
| Per-request cookie redirect leak | [GHSA-hg6j-4rv6-33pg](https://github.com/advisories/GHSA-hg6j-4rv6-33pg) | `aiohttp` client redirect handling | Whether cookies passed in the request call are forwarded after a cross-origin redirect controlled by the target. |
| Remote filename/path containment | [GHSA-jmmv-h3mp-59v8](https://github.com/advisories/GHSA-jmmv-h3mp-59v8) | `docling-core` remote fetch/cache handling | Whether server-controlled `Content-Disposition` filenames can escape the intended cache or fetch directory. |

## Recon workflow

### 1. Confirm version and reachability

Use source, lockfiles, and runtime evidence. Do not report from package presence alone.

```bash
# Python packages.
grep -R 'jupyter_enterprise_gateway\|docling-core\|aiohttp' -n requirements*.txt pyproject.toml poetry.lock uv.lock setup.cfg setup.py 2>/dev/null
python - <<'PY'
from importlib.metadata import version, PackageNotFoundError
for pkg in ['jupyter_enterprise_gateway', 'docling-core', 'aiohttp']:
    try:
        print(pkg, version(pkg))
    except PackageNotFoundError:
        pass
PY

# Node runner dependency and likely server port.
grep -R 'browserstack-runner\|test_server_port\|_log' -n package.json package-lock.json yarn.lock pnpm-lock.yaml browserstack.json . 2>/dev/null
npm ls browserstack-runner --depth=4 2>/dev/null

# Froxlor deployment clues in authorized infrastructure notes or source bundles.
grep -R 'froxlor/froxlor\|FroxlorRPC\|api_keys' -n composer.json composer.lock . 2>/dev/null
```

For network exposure, stay inside approved ranges and record only service metadata:

```bash
# BrowserStack runner defaults to TCP/8888 unless configured otherwise.
nmap -sT -Pn -p 8888 --open <authorized-host-or-range>

# Jupyter Enterprise Gateway commonly exposes an HTTP API; use owner-provided hosts first.
curl -i --max-time 5 https://<authorized-enterprise-gateway>/api/kernels
```

### 2. Jupyter Enterprise Gateway kernel-launch boundaries

Start with the lowest-risk proof: expression rendering, not command execution.

- Confirm the API path, authentication context, and kernel spec name in scope.
- Create a kernel request in a staging namespace with an inert `KERNEL_POD_NAME` canary such as `eg-canary-{{7*7}}`.
- Vulnerable behavior is evidence that the rendered pod/kernel name or error output contains the evaluated result instead of the literal braces.
- For YAML injection, use a harmless label/annotation canary rather than privileged pods, hostPath mounts, or service-account theft.
- For UID/GID policy, compare exact `0` versus normalization edge cases in a lab where launching as root cannot affect shared workloads.

Evidence worth capturing:

```bash
curl -sS -X POST 'https://<authorized-enterprise-gateway>/api/kernels' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: token <redacted-test-token>' \
  --data '{"name":"python_kubernetes","env":{"KERNEL_POD_NAME":"eg-canary-{{7*7}}"}}' | tee eg-response.json
```

Do not move from inert template proof to OS command execution, privileged pods, hostPath mounts, or secret access unless the owner has explicitly approved that escalation.

### 3. `browserstack-runner` local service boundary

Treat this as a developer-host exposure check. Useful findings usually show one of these paths:

- a CI job or developer workstation starts `browserstack-runner` and binds the test server to all interfaces;
- an internal network scan can reach the runner port from a different host;
- unauthenticated traversal can read a lab marker outside the project root;
- the `/_log` handler accepts untrusted JSON and reaches the evaluation path.

Safe file-read validation in a lab:

```bash
mkdir -p /tmp/bs-runner-lab/project /tmp/bs-runner-lab/outside
printf 'skillz-browserstack-canary\n' >/tmp/bs-runner-lab/outside/marker.txt
cd /tmp/bs-runner-lab/project
# Start the runner only in an isolated lab or approved dev host, then from another shell:
curl --path-as-is -sS 'http://127.0.0.1:8888/../outside/marker.txt'
```

For the RCE advisory, keep public testing to source and endpoint reachability unless the program explicitly allows local command execution. A strong report can use code evidence plus a request showing that unauthenticated `/_log` accepts attacker-controlled `arguments`; do not run shell commands on shared CI hosts.

### 4. Froxlor API 2FA drift

The operator question is whether the API authentication boundary matches the web-login boundary.

- Use a test account owned by the program.
- Enable TOTP for the account and confirm the web UI requires a second factor.
- Create or obtain a scoped test API key/secret for that same account.
- Send a benign API method call that reads only the test account profile or version metadata.
- Report if API key + secret succeeds without any 2FA challenge or 2FA-bound token exchange.

Do not use leaked keys, customer keys, or admin keys. If credentials are discovered during an assessment, pause and follow the program's credential-handling rules.

### 5. `aiohttp` per-request cookie redirect leakage

This is most useful when reviewing client integrations, webhook fetchers, OAuth helpers, or importers that call URLs influenced by another tenant.

Lab pattern:

1. controlled origin A returns a `302` to controlled origin B;
2. the client calls origin A with `aiohttp` `cookies={...}` on that request;
3. origin B logs whether the cookie appears after redirect.

A report should include the exact call site and prove that sensitive per-request cookies, not ordinary cookie-jar state, cross an origin boundary. Avoid testing with real session cookies; use canary values.

### 6. Docling remote filename and path containment

This extends the existing Docling resource-fetch guidance: the server response can influence local filename resolution.

- Build a tiny controlled HTTP server that returns a document body plus a `Content-Disposition` filename containing traversal or absolute-path markers.
- Point only a lab/staging Docling pipeline at that URL.
- Watch the intended cache directory and an outside marker path.
- Vulnerable behavior is any file materialization outside the expected cache/fetch root.

Keep payloads small and inert; do not combine this with metadata-service SSRF or sensitive local-file targets unless explicitly authorized.

## Reporting heuristic

Frame each finding around the violated trust boundary:

- **Expected boundary:** environment variables, API keys, redirect responses, filenames, and local test-runner requests remain inert data unless explicitly authorized, normalized, and scoped.
- **Observed bypass:** a specific endpoint or call site lets attacker-controlled input cross into template rendering, YAML structure, root UID/GID selection, file serving, command evaluation, API access without second factor, cookie forwarding, or cache-path resolution.
- **Impact:** Kubernetes service-account or workload control, developer/CI host file read or code execution, hosting-panel API overreach, credential leakage across redirects, or document-ingestion file write/read primitive.
- **Evidence:** affected package version, reachable endpoint or code path, exact inert canary request, redacted response/body/log evidence, and patched-version or configuration control.

## Scope and safety notes

- Keep Jupyter and browserstack execution checks in lab, staging, or explicitly approved hosts.
- Do not create privileged pods, mount host paths, steal service-account tokens, or run shell commands as proof without written authorization.
- Do not use real cookies or secrets for redirect and API-boundary tests; use canaries.
- Do not scan broad internal ranges for developer runner ports unless the assessment scope allows it.
- Treat document-ingestion URL tests as SSRF-adjacent: use controlled canary servers and avoid internal addresses by default.
