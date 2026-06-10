# Litestar and Fission builder boundary checks

Source: hourly offensive-security scan, 2026-06-10. Primary entries: GitHub advisories [GHSA-3qmc-cj7q-62hv](https://github.com/advisories/GHSA-3qmc-cj7q-62hv) / CVE-2026-48061 for Litestar allowed-host bypass via `X-Forwarded-Host`, [GHSA-542p-wvx7-72m4](https://github.com/advisories/GHSA-542p-wvx7-72m4) / CVE-2026-48060 for Litestar CSRF token HTML injection, and [GHSA-7pjr-qpvh-m339](https://github.com/advisories/GHSA-7pjr-qpvh-m339) / CVE-2026-46618 for Fission builder command execution through `Environment.spec.builder.command`.

This batch is durable for operators because it covers two reusable classes of offensive testing:

- framework trust in client-controlled host and cookie-derived CSRF-token material;
- serverless build pipelines where tenant-editable environment objects cross into command execution inside builder pods.

## Litestar host validation via `X-Forwarded-Host`

The Litestar allowed-host advisory describes `AllowedHostsMiddleware` falling back to `X-Forwarded-Host` when `Host` is absent. That is a useful bug-hunting pattern beyond this single framework: applications often validate one host source but later generate links, cache entries, redirects, or routing decisions from another client-controlled host source.

### Authorized validation

Use only owned accounts and canary domains.

```http
GET /password-reset HTTP/1.0
X-Forwarded-Host: allowed.example
```

Check whether the request bypasses allowed-host rejection when `Host` is missing and whether any downstream behavior uses attacker-supplied host material:

- password-reset or email confirmation absolute URLs;
- redirect targets and canonical URL helpers;
- cache keys, tenant routing, or backend selection;
- audit logs or signed URLs that include the resolved host.

A strong report proves both sides of the boundary: the request should have been rejected by the host allowlist, and a security-relevant sink used the client-controlled forwarded host.

## Litestar CSRF cookie rendered as trusted markup

The CSRF-token advisory describes Litestar applications that use templates, enable CSRF protection, enable CSRF hidden inputs, and render a cookie-sourced CSRF value without normal template escaping. The reusable workflow is to test whether security-token helpers turn client-controlled cookie material into trusted page markup.

### Authorized validation

1. Find a Litestar form page that uses server-side templates and CSRF input helpers.
2. Change only your own `csrftoken` cookie to a benign marker such as:

   ```text
   "><b>skillz-csrf-canary</b>
   ```

3. Reload the form and inspect whether the marker is rendered as markup inside the hidden input or surrounding page.
4. If program rules allow XSS validation, escalate only in a lab or with inert proof payloads. Do not target other users' sessions.

Report this as **client-controlled cookie material rendered as trusted template markup**. Avoid claiming stored XSS, account takeover, or CSRF bypass unless you independently prove those chains.

## Fission builder command boundary

The Fission builder advisory describes `Environment.spec.builder.command` flowing into `exec.Command(...)` after basic field splitting. A subject who can create or update Fission `Environment` CRDs in a namespace observed by `buildermgr` can select an executable inside the builder image and cause code execution in the builder pod context.

This is distinct from previously covered Fission router and runtime-token issues: the key boundary is **control-plane environment metadata to builder-pod command execution and package artifact mutation**.

### What to map

1. Identify Fission deployments and versions; this builder issue is fixed in Fission `1.23.0`.
2. Enumerate who can `create`, `update`, or GitOps-merge `Environment` objects in Fission namespaces.
3. Map builder pod service account, namespace, mounted package volumes, and any shared `/packages` paths.
4. Confirm which functions/packages use the editable environment.
5. Determine whether artifact mutation could influence subsequent function specialization or deployment archive uploads.

### Replayable validation boundary

Use a lab namespace or explicit customer approval. Do not mutate production packages or execute shell payloads against shared builders.

1. Create a disposable environment and package tied to a canary function.
2. Set the builder command to an inert absolute executable allowed by the test image, or a purpose-built canary binary/script that writes a marker such as `skillz-builder-canary` into a temporary artifact path.
3. Trigger a build for only the canary package.
4. Confirm the marker appears in the canary artifact or builder logs.
5. Remove the canary environment/package and preserve only redacted command, namespace, and marker evidence.

A finding is high-quality when it shows that a non-admin platform actor or compromised CI/GitOps path can cross from declarative `Environment` control into executable builder behavior.

## Reporting heuristics

- For Litestar host findings, include the raw request shape, host allowlist expectation, observed bypass, and the downstream sink that consumed the forwarded host.
- For Litestar CSRF rendering, include framework/template configuration, the benign cookie marker, and a screenshot or DOM snippet showing markup interpretation.
- For Fission builder findings, include the actor with `Environment` write, namespace, Fission version, builder service account, canary command, canary artifact/log proof, and why the package or function boundary matters.
- Keep proof narrow: no real tokens, customer package archives, production command output, or other users' cookies should appear in reports or wiki evidence.
