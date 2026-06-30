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

## June 30 Fission namespace and trigger boundary update

Later GitHub advisories added three adjacent Fission control-plane boundaries: [GHSA-gc3j-79f2-7vvw](https://github.com/advisories/GHSA-gc3j-79f2-7vvw) / CVE-2026-49822 for cross-namespace `KubernetesWatchTrigger` event leakage, [GHSA-vjhc-cf4p-72q4](https://github.com/advisories/GHSA-vjhc-cf4p-72q4) / CVE-2026-49821 for `Package.spec.environment.namespace` crossing into another tenant's builder pod, and [GHSA-7m8x-qg2j-4m3v](https://github.com/advisories/GHSA-7m8x-qg2j-4m3v) for `MessageQueueTrigger` secret materialization plus arbitrary connector `PodSpec` merge.

These belong with the existing Fission builder workflow because the durable pattern is the same: tenant-editable Fission CRDs are interpreted by higher-privilege controllers and can cross namespace, service-account, secret, event-stream, or pod-spec boundaries.

### What to add to Fission assessments

| Advisory | Fission object | Crossed boundary | Safe evidence |
| --- | --- | --- | --- |
| [GHSA-gc3j-79f2-7vvw](https://github.com/advisories/GHSA-gc3j-79f2-7vvw) | `KubernetesWatchTrigger` | user-controlled `spec.namespace` or empty namespace caused the cluster-scoped watcher to POST Pod/Service/Job events from another namespace or all namespaces | lab namespace A trigger receiving synthetic namespace B canary events; no real workload metadata |
| [GHSA-vjhc-cf4p-72q4](https://github.com/advisories/GHSA-vjhc-cf4p-72q4) | `Package` | `spec.environment.namespace` selected another tenant's `Environment` and ran build steps in the victim builder pod | marker-only build log from a disposable victim namespace; never read service-account tokens |
| [GHSA-7m8x-qg2j-4m3v](https://github.com/advisories/GHSA-7m8x-qg2j-4m3v) | `MessageQueueTrigger` | controller copied named Secret values into Deployment envvars and merged user-controlled `PodSpec` fields without a tight allowlist | synthetic Secret key appearing in a lab Deployment pod template, or inert image/command override proof |

### Replayable namespace-control harness

1. Stand up a disposable Fission cluster or customer-approved lab with two namespaces: `attacker-a` and `victim-b`.
2. Grant the tester only the specific tenant role under test, such as `kuberneteswatchtriggers/create`, `packages/create`, or `messagequeuetriggers/create` in `attacker-a`.
3. Seed only harmless canaries in `victim-b`: a fake Pod/Service/Job label, a throwaway Environment and Package, and a Secret such as `skillz-fission-canary=not-a-secret`.
4. Attempt the exact CRD boundary:
   - set `KubernetesWatchTrigger.spec.namespace` to `victim-b` or omit it to test all-namespace defaulting;
   - set `Package.spec.environment.namespace` to `victim-b` and use an inert build lifecycle marker;
   - set `MessageQueueTrigger.spec.secret` to the canary Secret and, separately, set a harmless `PodSpec` override such as a canary image or command.
5. Positive evidence should be limited to event receipt, marker-only build output, Deployment manifest fields, or a rejected/accepted controller decision. Do not collect pod specs from real workloads, ConfigMaps, service-account tokens, or production Secrets.
6. Repeat on Fission `v1.24.0` or later as a negative control: namespace equality checks should reject cross-namespace references, empty watch namespaces should bind to the trigger namespace, Secret values should remain `ValueFrom` references, and PodSpec merges should be allowlisted.

## June 30 late Fission podspec and package-reference update

The later published Fission wave added seven adjacent controller-boundary advisories: [GHSA-3r8v-2xmj-5c39](https://github.com/advisories/GHSA-3r8v-2xmj-5c39) / CVE-2026-49823, [GHSA-cvw6-gfvv-953q](https://github.com/advisories/GHSA-cvw6-gfvv-953q) / CVE-2026-49824, [GHSA-wmgg-3p4h-48x7](https://github.com/advisories/GHSA-wmgg-3p4h-48x7) / CVE-2026-50545, [GHSA-v455-mv2v-5g92](https://github.com/advisories/GHSA-v455-mv2v-5g92) / CVE-2026-50563, [GHSA-gx55-f84r-v3r7](https://github.com/advisories/GHSA-gx55-f84r-v3r7) / CVE-2026-50564, [GHSA-8wcj-mfrc-jx5q](https://github.com/advisories/GHSA-8wcj-mfrc-jx5q) / CVE-2026-50565, and [GHSA-m63v-2g9w-2w6v](https://github.com/advisories/GHSA-m63v-2g9w-2w6v) / CVE-2026-50566.

Promote these as one Fission tenant-control-plane workflow, not seven isolated alerts. The durable operator pattern is **tenant-writable Function/Environment metadata crossing into other namespaces, package archives, service-account tokens, or privileged Kubernetes pod fields**.

| Advisory | Fission object / field | Crossed boundary | Safe evidence |
| --- | --- | --- | --- |
| [GHSA-3r8v-2xmj-5c39](https://github.com/advisories/GHSA-3r8v-2xmj-5c39) | `Function.spec.package.packageref.namespace` | attacker namespace Function caused the fetcher sidecar to read a Package from another namespace | disposable victim Package whose archive contains only `skillz-package-canary`; prove marker appears in attacker pool pod path, not real source |
| [GHSA-cvw6-gfvv-953q](https://github.com/advisories/GHSA-cvw6-gfvv-953q) | `Function.spec.environment.namespace` | attacker namespace Function selected another namespace's Environment/runtime image | canary Environment image or log marker from a lab victim namespace; do not inspect victim images for secrets |
| [GHSA-wmgg-3p4h-48x7](https://github.com/advisories/GHSA-wmgg-3p4h-48x7), [GHSA-gx55-f84r-v3r7](https://github.com/advisories/GHSA-gx55-f84r-v3r7) | `Environment.spec.runtime.podSpec` / `spec.builder.podSpec` | CRD podspec passthrough propagated `hostPID`, `hostNetwork`, `hostIPC`, `hostPath`, `serviceAccountName`, or privileged container settings | admission decision table and rendered pod template in a throwaway cluster; avoid host mounts and node escape |
| [GHSA-v455-mv2v-5g92](https://github.com/advisories/GHSA-v455-mv2v-5g92) | `Function.spec.podspec` with container executor | Function-level podspec merged dangerous Kubernetes fields into generated Deployments | rejected/accepted canary fields plus pod-template diff for a disposable Function only |
| [GHSA-8wcj-mfrc-jx5q](https://github.com/advisories/GHSA-8wcj-mfrc-jx5q) | builder pod `ServiceAccountName: fission-builder` with default automount | user-supplied builder container inherited the builder service-account token | prove the mount path exists with a fake-token lab service account or pod template evidence; never print real token bytes |
| [GHSA-m63v-2g9w-2w6v](https://github.com/advisories/GHSA-m63v-2g9w-2w6v) | `Environment.spec.runtime.container.securityContext` / `spec.builder.container.securityContext` | standalone Container securityContext bypassed PodSpec-only validation | canary `securityContext` accept/reject matrix on affected and fixed versions; no privileged host operations |

### Podspec and cross-namespace harness

1. Use a disposable Fission cluster with two namespaces, `attacker-a` and `victim-b`, and grant the tester only the tenant role being assessed.
2. Seed `victim-b` with harmless resources: a Package archive containing `skillz-package-canary`, an Environment using a canary image/label, and a fake Secret/ConfigMap if needed for already-covered trigger tests.
3. For reference-boundary tests, create Functions in `attacker-a` that point only the tested namespace field at `victim-b`. Positive evidence is marker-only package or environment selection in the generated attacker workload.
4. For podspec/securityContext tests, submit one dangerous-looking but inert field at a time and capture whether admission, webhook update paths, and controller-generated pod templates accept or reject it. Do not mount host paths, request real privileged containers, or connect to host namespaces outside a lab designed for that purpose.
5. For service-account automount checks, use pod-template evidence or a fake lab token marker. Never capture Kubernetes service-account tokens, ConfigMaps, Secrets, or package archives from customer workloads.
6. Re-run on the fixed release as a negative control: cross-namespace references should be rejected or scoped to the caller namespace, update webhooks should cover the same fields as create, service-account tokens should not automount into user-supplied builder containers, and both PodSpec and standalone Container fields should be allowlisted.

## Reporting heuristics

- For Litestar host findings, include the raw request shape, host allowlist expectation, observed bypass, and the downstream sink that consumed the forwarded host.
- For Litestar CSRF rendering, include framework/template configuration, the benign cookie marker, and a screenshot or DOM snippet showing markup interpretation.
- For Fission builder findings, include the actor with `Environment` write, namespace, Fission version, builder service account, canary command, canary artifact/log proof, and why the package or function boundary matters.
- For Fission namespace/trigger findings, include the exact CRD kind, actor RBAC, source namespace, target namespace, controller service account, canary object name, expected namespace confinement, actual controller behavior, and fixed-version negative control.
- For Fission podspec/package-reference findings, include the exact CRD path, create/update verb tested, controller-generated pod-template diff, service-account involved, canary package/environment marker, and fixed-version rejection. Keep node-escape language tied to lab evidence; do not imply production host compromise from an admission decision alone.
- Keep proof narrow: no real tokens, customer package archives, production command output, production workload event payloads, real Secrets, or other users' cookies should appear in reports or wiki evidence.
