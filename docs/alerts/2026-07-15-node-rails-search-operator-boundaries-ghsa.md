# Node host-inventory, Rails component, search deserialization, and operator boundary checks

Source: hourly offensive-security scan, 2026-07-15 GitHub advisory wave. Primary entries: [GHSA-5xpp-75jx-m839](https://github.com/advisories/GHSA-5xpp-75jx-m839) / CVE-2026-50289, [GHSA-97jw-64cj-jc58](https://github.com/advisories/GHSA-97jw-64cj-jc58) / CVE-2026-54498, [GHSA-9h85-g7w3-rh49](https://github.com/advisories/GHSA-9h85-g7w3-rh49) / CVE-2026-54497, [GHSA-r3hx-x5rh-p9vv](https://github.com/advisories/GHSA-r3hx-x5rh-p9vv), [GHSA-398h-7f66-3h4p](https://github.com/advisories/GHSA-398h-7f66-3h4p) / CVE-2026-54495, [GHSA-qmc5-gv6v-8p22](https://github.com/advisories/GHSA-qmc5-gv6v-8p22) / CVE-2026-50266, [GHSA-8f39-v287-78jf](https://github.com/advisories/GHSA-8f39-v287-78jf) / CVE-2026-50076, and [GHSA-76qh-xr7q-h39m](https://github.com/advisories/GHSA-76qh-xr7q-h39m) / CVE-2026-44393.

This batch is durable because it exposes repeatable operator boundaries: local host configuration parsed into shell commands by inventory libraries, Rails component wrapper hooks bypassing the normal HTML-safety boundary, reused render objects retaining cross-request context, indexed content flowing into Python `eval()` during search result deserialization, Kubernetes operators resolving cross-namespace specs, tenant network-service flags bypassing Neutron shared-network controls, Java deserializers reaching classpath hooks despite type filters, and OpenStack RPC clients validating CA chains without binding broker hostnames.

!!! warning "Authorized validation only"
    Keep proofs to disposable Linux hosts, Rails/Django/OpenStack/Kubernetes labs, synthetic search documents, fake feature-flag specs, throwaway Neutron networks, inert serialized Java fixtures, lab CAs, and marker-only callbacks. Do not modify production network configuration, execute shell payloads on production agents, collect real tenant traffic, dump real feature-flag tokens, read live search content, capture RabbitMQ credentials, or run destructive cloud control-plane operations.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-5xpp-75jx-m839](https://github.com/advisories/GHSA-5xpp-75jx-m839) / CVE-2026-50289 | `systeminformation` `networkInterfaces()` on Linux | `interfaces(5)` `source` directive path is read from local system state and interpolated unquoted into an `execSync()` shell string while collecting DHCP state | Treat host-inventory and monitoring APIs as execution sinks when they parse mutable OS config before shelling out. Prove only with a lab `interfaces` source chain and inert marker command. |
| [GHSA-97jw-64cj-jc58](https://github.com/advisories/GHSA-97jw-64cj-jc58) / CVE-2026-54498 | Rails ViewComponent `around_render` and collection rendering | `around_render` return values bypass the escaping applied to normal `#call` output; collection rendering can join raw strings and mark the aggregate `html_safe` | Add wrapper/hook output-safety checks to Rails component reviews, especially where user text is conditionally returned from instrumentation or wrapper code. |
| [GHSA-9h85-g7w3-rh49](https://github.com/advisories/GHSA-9h85-g7w3-rh49) / CVE-2026-54497 | Rails ViewComponent reused instances, slots, and collections | Mutable component instances retain helpers, controller, request, view flow, format, variant, and slot context across renders when reused across requests/users/threads | Test cached component instances as cross-request trust boundaries: authorization-aware UI, host-derived links, and slot helpers should not reuse another user's render context. |
| [GHSA-r3hx-x5rh-p9vv](https://github.com/advisories/GHSA-r3hx-x5rh-p9vv) | `django-haystack` Elasticsearch backend | Documents stored under `index_fieldname` aliases miss logical-field converters and fall through to `_to_python()` -> `eval()` on raw Elasticsearch values | For search-backed apps, trace indexed user content all the way back through result deserialization, not only into the indexer. Synthetic document values can prove code-evaluation reachability without exposing real content. |
| [GHSA-398h-7f66-3h4p](https://github.com/advisories/GHSA-398h-7f66-3h4p) / CVE-2026-54495 | OpenFeature Operator `FeatureFlagSource` / `InProcessConfiguration` annotations | A tenant workload can reference `{namespace}/{name}` sources; the cluster-scoped operator materializes inline spec contents such as `envVars`, bearer-token fields, and sync URIs into the referencing workload | In multi-tenant Kubernetes assessments, test operator annotation syntax as an authorization surface, not just core Kubernetes RBAC. |
| [GHSA-qmc5-gv6v-8p22](https://github.com/advisories/GHSA-qmc5-gv6v-8p22) / CVE-2026-50266 | OpenStack Neutron shared-network port policy | Project managers can set trusted `device_owner` values such as `network:dhcp` on ports attached to another project's shared network | Add shared-network tenant controls for device-owner semantics; marker ports can show whether anti-spoofing/security-group behavior changes without attacking other tenants. |
| [GHSA-8f39-v287-78jf](https://github.com/advisories/GHSA-8f39-v287-78jf) / CVE-2026-50076 | Apache Fory Java SDK replace-resolve path | Crafted serialized data can bypass class registration, type checking, and disallow lists, then invoke classpath-present `readResolve` / `readExternal` hooks | Treat serializer type filters as bypassable until a fixture proves the exact Java hook path is unreachable. Keep proofs to inert classes compiled into a lab harness. |
| [GHSA-76qh-xr7q-h39m](https://github.com/advisories/GHSA-76qh-xr7q-h39m) / CVE-2026-44393 | OpenStack `oslo.messaging` RabbitMQ TLS client | CA validation is enabled, but the expected broker hostname is not passed into TLS verification; any deployment-CA-signed certificate can impersonate the broker | For OpenStack control planes, verify TLS identity binding separately from chain trust. Use lab CAs and fake brokers only; do not intercept production RPC traffic. |

## Replayable validation boundaries

### Linux host-inventory command-boundary check

1. Build a disposable Debian/Ubuntu-style Linux VM or container with an affected `systeminformation` release below `5.31.7` and a minimal Node harness that calls `networkInterfaces()`, `getStaticData()`, or `getAllData()`.
2. Back up the lab `/etc/network/interfaces` file, then create a controlled `source` chain that references only a temporary test file under a lab directory.
3. Insert an inert shell-metacharacter marker in the sourced path, such as writing a fixed string to a temporary file owned by the lab process. Do not use reverse shells, network callbacks, credential reads, or persistence paths.
4. Run the harness and record whether the marker proves that the parsed `source` token reached `execSync()` unquoted.
5. Add controls for patched `5.31.7`, a benign `source` path, a file containing `source-directory`, a process running as an unprivileged user, and Linux hosts that do not use `/etc/network/interfaces`.

Report this as **mutable host network config -> inventory library parser -> unquoted shell command during DHCP-state collection**. Evidence should include affected package version, source-chain class, harness API called, marker-only effect, process user if safely visible, and patched negative control.

### Rails ViewComponent output-safety and stale-context checks

1. Stand up a disposable Rails app using an affected ViewComponent version below `4.12.0` with one low-privilege and one high-privilege lab user.
2. For the `around_render` issue, create a component whose normal `#call` output containing synthetic user text is escaped, then wrap or replace output through `around_render` with the same marker. Record whether the wrapper return is emitted raw.
3. Repeat in collection rendering where joined component output may be marked `html_safe` as a group. Use harmless DOM markers rather than credential-harvesting scripts.
4. For the stale-context issue, intentionally reuse the same component, collection, or spacer instance across two lab requests with different users, hosts, and helper-visible state.
5. Record whether authorization-aware UI, links, slot content, request details, or host-derived helpers from User A appear in User B's render.
6. Add controls for patched `4.12.0`, fresh component instances per render, non-collection rendering, escaped `#call` output, concurrent versus sequential renders, and templates that never use user-controlled data.

Report these as **component wrapper return bypasses escape boundary** and **cached mutable component instance retains prior request context**. Evidence should be route, component class, role/host pair, marker text or DOM marker, render mode, and patched or fresh-instance negative controls.

### Search-result deserialization `eval()` check

1. Build a Django/django-haystack lab with the Elasticsearch backend and an affected release below `3.4.0`.
2. Define a `SearchField` with an `index_fieldname` alias different from the logical field name, then index a synthetic object whose aliased field value is fully controlled by the lab user.
3. Use an inert Python expression marker that proves evaluation without shelling out or reading files, such as constructing a unique string through safe built-ins observable in the result path.
4. Trigger a search that returns the document and observe whether `_process_results()` routes the aliased value through `_to_python()` and `eval()` instead of the field converter.
5. Add controls for patched `3.4.0`, matching logical/index field names, non-Elasticsearch backends, fields with explicit converters reached correctly, and ordinary literal strings that should deserialize without evaluation.

Report this as **indexed attacker-controlled field alias -> converter lookup miss -> raw search result value evaluated in Django process**. Evidence should include index schema, alias mismatch, stored marker value class, search route, evaluation result, and patched negative control. Do not index shell commands or production content.

### Kubernetes operator cross-namespace materialization check

1. Use a multi-tenant lab cluster with two namespaces representing separate tenants and the affected OpenFeature Operator deployed with its normal cluster-scoped permissions.
2. In tenant A, create a `FeatureFlagSource` or `InProcessConfiguration` containing only synthetic inline spec markers: fake `envVars`, fake `httpSyncBearerToken`, and an owned sync URI.
3. In tenant B, create a controller-owned workload annotated with `openfeature.dev/featureflagsource: tenant-a/name` or the documented cross-namespace syntax in scope.
4. Observe only whether tenant A's inline spec markers are materialized into tenant B's pod, sidecar arguments, environment, generated ConfigMap, or operator-managed resources.
5. Add controls for no OwnerReference, same-namespace references, patched operator behavior when available, missing source names, RBAC denying tenant B source reads directly, and `secretKeyRef`/`configMapKeyRef` values that should remain namespace-local.

Report this as **tenant-controlled workload annotation -> cluster-scoped operator resolves another namespace's feature-flag spec -> inline secret-like fields copied into tenant workload**. Evidence should be namespace pair, annotation value, marker field class, materialization location, and direct-RBAC negative control.

### OpenStack shared-network and RPC identity checks

1. Build an OpenStack lab with at least two projects sharing a network, Neutron below `28.0.1`, and project-manager credentials that do not own the shared network.
2. Attempt to create or update only a disposable port on the shared network with a trusted-looking `device_owner` value such as `network:dhcp`. Do not attach it to production subnets or issue traffic against other tenants.
3. Record whether Neutron accepts the trusted device owner and whether lab-only anti-spoofing/security-group behavior differs from an ordinary tenant port.
4. Separately, in an oslo.messaging/RabbitMQ TLS lab, configure a deployment CA and present a fake broker certificate signed by that CA but issued for the wrong hostname.
5. Observe whether affected clients complete TLS and attempt RPC/notification traffic to the fake broker. Log only connection metadata and marker messages; do not capture real service credentials or production payloads.
6. Add controls for patched Neutron policies, network-owner credentials, ordinary project-member credentials, correct and incorrect broker hostnames, certificates signed by an untrusted CA, and non-RabbitMQ transports.

Report these as **shared-network project-manager role -> trusted service-port semantics on another project network** and **CA-valid but hostname-wrong broker certificate -> OpenStack RPC client accepts impersonated RabbitMQ endpoint**.

### Java serializer hook-bypass check

1. Build a local Apache Fory Java harness below `1.1.0` with class registration, type checking, and a disallow list configured to match the target's expected hardening posture.
2. Compile a lab-only class with inert `readResolve` or `readExternal` behavior that emits a marker string or toggles an in-memory flag. Do not include file, network, process, reflection, or classloader side effects.
3. Feed a crafted Fory serialized fixture through the replace-resolve path and record whether the hook executes despite the configured filters.
4. Add controls for patched `1.1.0`, absent lab marker class, class not on the classpath, filters that should block the type, and ordinary registered benign classes.

Report this as **untrusted Fory serialized bytes -> replace-resolve path bypasses type filters -> classpath hook invocation**. Evidence should be library version, filter posture, fixture class name, inert hook result, and patched negative control.

## Reporting notes

- Lead with preconditions: who can modify `/etc/network/interfaces` or sourced files, whether components are reused across requests, who controls indexed content, namespace tenancy assumptions, OpenStack project roles, serializer exposure, and control-plane network position.
- Prefer decision tables over payload dumps: input source, parser stage, trust boundary, sink, marker effect, and negative control.
- Redact host paths outside lab temp directories, tenant names, feature-flag tokens, RabbitMQ credentials, OpenStack endpoints, search documents, and component source code that reveals customer business logic.
- The same scan included Pomerium zstd memory exhaustion, Datadog W3C baggage parsing denial-of-service advisories, and `serde_with` panic behavior. They were marked processed without promotion because this run did not identify a safe, durable offensive workflow beyond bounded availability testing.
