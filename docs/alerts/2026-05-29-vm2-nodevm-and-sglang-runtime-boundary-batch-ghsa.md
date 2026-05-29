# vm2 / NodeVM sandbox escapes and SGLang multimodal runtime boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-rp36-8xq3-r6c4](https://github.com/advisories/GHSA-rp36-8xq3-r6c4) / CVE-2026-47140, [GHSA-r9pm-gxmw-wv6p](https://github.com/advisories/GHSA-r9pm-gxmw-wv6p) / CVE-2026-47139, [GHSA-6j2x-vhqr-qr7q](https://github.com/advisories/GHSA-6j2x-vhqr-qr7q) / CVE-2026-47210, [GHSA-m4wx-m65x-ghrr](https://github.com/advisories/GHSA-m4wx-m65x-ghrr) / CVE-2026-47137, [GHSA-c4cf-2hgv-2qv6](https://github.com/advisories/GHSA-c4cf-2hgv-2qv6) / CVE-2026-47209, [GHSA-m5q2-4fm3-vfqp](https://github.com/advisories/GHSA-m5q2-4fm3-vfqp) / CVE-2026-47135, [GHSA-76w7-j9cq-rx2j](https://github.com/advisories/GHSA-76w7-j9cq-rx2j) / CVE-2026-47208, [GHSA-v6mx-mf47-r5wg](https://github.com/advisories/GHSA-v6mx-mf47-r5wg) / CVE-2026-47131, [GHSA-36m8-w8qf-g76p](https://github.com/advisories/GHSA-36m8-w8qf-g76p) / CVE-2026-7304, [GHSA-qwrp-wghp-94q2](https://github.com/advisories/GHSA-qwrp-wghp-94q2) / CVE-2026-7302, and [GHSA-gwv6-pq6m-p3rq](https://github.com/advisories/GHSA-gwv6-pq6m-p3rq) / CVE-2026-7301.

This batch is durable because it captures two reusable operator patterns: JavaScript sandbox security-boundary validation when products execute user-controlled code, and LLM/multimodal serving planes where model-runtime helper features introduce unauthenticated file write, pickle/dill deserialization, or scheduler socket exposure.

## What changed

- **NodeVM builtin deny-list bypass to host RCE** — `vm2 <=3.11.3` did not deny `process` or `inspector/promises` as dangerous builtins. Sandboxed code with permissive `require.builtin` settings can use `require('process').getBuiltinModule('child_process')` or the inspector protocol to execute host-side JavaScript or spawn commands. Patched in `vm2@3.11.4`.
- **NodeVM network builtin exclusion bypass** — public modules such as `http`, `net`, `tls`, and `dns` can be excluded, but internal builtins such as `_http_client`, `_http_server`, and related underscored modules were still reachable. This is not host RCE by itself, but restores outbound/listening network capability and can turn a sandboxed plugin surface into an SSRF or internal-service probe.
- **vm2 promise and WebAssembly sandbox escapes** — multiple VM escapes in `vm2 <=3.11.3` abuse Promise species handling, JSPI-backed WebAssembly promises, host-originated errors, and prototype/constructor chains to reach host `process` and command execution.
- **vm2 nesting/default configuration bypass** — `NodeVM({ nesting: true })` without an explicit `require` option bypassed the guard intended to block `nesting:true` with `require:false`, allowing an inner `NodeVM` to re-enable dangerous builtins such as `child_process`.
- **vm2 bridge symbol/property injection** — missing write-side checks for dangerous cross-realm `Symbol.for(...)` keys and a proxy `set` trap that ignores the `receiver` parameter can let sandbox code mutate host objects, hijack `util.promisify.custom`, or create semantic confusion on host-side functions and streams.
- **SGLang custom logit processor RCE** — when SGLang is launched with `--enable-custom-logit-processor`, attacker-controlled objects are deserialized with `dill.loads()` in the multimodal generation runtime.
- **SGLang upload path traversal** — SGLang multimodal endpoints accepted upload filenames containing `../` sequences, allowing unauthenticated arbitrary file writes anywhere the server process can write.
- **SGLang scheduler pickle RCE** — the multimodal scheduler ROUTER socket binds to `0.0.0.0` by default and deserializes incoming messages with `pickle.loads()`, making exposed scheduler ports direct RCE surfaces.

## Operator triage

1. **Find vm2-as-boundary products:** search for apps, workflow engines, plugin systems, CMS extensions, agent tools, notebook platforms, and SaaS scripting features that advertise user-supplied JavaScript isolation with `vm2`, `VM`, or `NodeVM`.
2. **Classify the sandbox configuration:** capture whether code uses `NodeVM` versus `VM`, whether `require` is enabled, whether `require.builtin` includes `*`, `process`, `inspector/promises`, or public network modules, and whether `nesting:true` is present.
3. **Identify host-object crossings:** prioritize products that pass privileged host functions, API clients, file handles, stream objects, or callback-style helpers into the sandbox. These are stronger candidates for bridge/symbol confusion than pure string-only evaluation.
4. **Check runtime version gates:** JSPI/WebAssembly promise paths depend on newer Node runtimes exposing `WebAssembly.promising` / `WebAssembly.Suspending`; record Node version alongside `vm2` version.
5. **Find SGLang exposure:** search for internet-facing SGLang deployments, LLM gateways, research demos, Kubernetes services, and inference clusters exposing HTTP multimodal routes or internal scheduler ports.
6. **Flag risky SGLang launch modes:** `--enable-custom-logit-processor`, unauthenticated multimodal uploads, and scheduler ROUTER sockets reachable beyond localhost are high-value validation targets.

## Replayable validation boundaries

### vm2 / NodeVM sandbox-boundary checks

- **Version and config proof first:** obtain package/version evidence from lockfiles, dependency manifests, admin diagnostics, container images, or response metadata before attempting any escape payload.
- **Use benign command markers:** in an authorized lab or dedicated tenant, prove host execution with harmless markers such as `id`, `whoami`, writing a canary file in a disposable temp directory, or reading a synthetic environment variable. Do not access secrets or sensitive files.
- **Builtin-denylist check:** if `require.builtin` allows wildcard or broad builtins, compare blocked direct `require('child_process')` with indirect `require('process').getBuiltinModule('child_process')` or `inspector/promises` behavior.
- **Network-bypass check:** when network modules are intentionally excluded, use a tester-owned local listener or canary HTTP service to compare direct `http`/`net` denial against `_http_client` or `_http_server` reachability. Keep the impact to capability bypass or authorized SSRF proof.
- **Nesting check:** for `NodeVM({ nesting:true })` candidates, confirm whether omitting `require` re-enables inner-VM builtins. Report this as a configuration-dependent escape, not as universally exploitable vm2 usage.
- **Bridge/symbol check:** where host callbacks are exposed, use harmless host functions and verify whether sandbox-side writes to `Symbol.for('nodejs.util.promisify.custom')` or inherited-property writes alter host-side behavior. Avoid mutating production objects.

### SGLang runtime-boundary checks

- **Service mapping:** identify public HTTP routes, multimodal upload endpoints, model worker ports, scheduler/router sockets, and pod/service exposure. Record whether ports bind to `0.0.0.0`, localhost, or a private cluster network.
- **Custom logit processor proof:** only in a scoped lab, send a minimal serialized object that creates a benign marker through the documented custom-logit path. Do not run destructive commands or deploy persistent payloads.
- **Upload traversal proof:** use a canary filename such as `../sglang-traversal-canary.txt` against a disposable instance and verify write location with filesystem access you control. On production targets, stop at filename normalization evidence unless arbitrary write validation is explicitly authorized.
- **Scheduler pickle proof:** treat exposed ROUTER sockets as critical. In normal bug-bounty scopes, prove reachability and unsafe deserialization from a lab mirror or with non-executing malformed-pickle behavior; avoid sending code-executing pickles to production infrastructure.

## Reporting heuristics

- For vm2 findings, include the product surface that accepts code, sandbox library/version, Node version, `VM`/`NodeVM` configuration, allowed builtins, host objects exposed to the sandbox, exact benign proof, and why the sandbox is a security boundary for the application.
- Separate **host RCE** from **capability bypass**. The `_http_*` NodeVM issue is strongest when the intended policy blocks network access and the bypass reaches sensitive internal services under authorization.
- For bridge/symbol issues, report the specific host object passed into the sandbox and the host-side semantic change observed. This makes impact clearer than a generic vm2 version finding.
- For SGLang, include launch flags, package version, exposed port/route, authentication state, deployment context, canary proof, and whether the issue is HTTP unauthenticated, scheduler-port unauthenticated, or configuration-gated.
- Tie SGLang impact to realistic inference-host privileges: model files, API credentials, mounted datasets, cloud metadata, internal control planes, and Kubernetes service-account context only when safely and explicitly validated.

## Notes on skipped items from this scan

- ExifReader ICC `mluc` memory blowup (GHSA-h64w-w9pr-82m4 / CVE-2026-8813) and compressed-metadata decompression limits (GHSA-rr89-w3h9-m66j / CVE-2026-8814) were reviewed as image-parser resource-exhaustion issues. They may matter in programs that reward DoS, but they are not standalone Skillz operator guidance for this taxonomy.
- vm2 stack-trace formatter invariant drift (GHSA-q3fm-4wcw-g57x) was tracked as hardening context and not promoted as a standalone exploit path because the advisory itself describes limited immediate impact.
- CISA KEV stayed on catalog `2026.05.28`; PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits, and Disclosed had no separate promotable deltas in this pass.
