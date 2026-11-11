# vm2 sandbox breakout via indirect-call dangerous-mutator shadowing, operator validation

**Date reviewed:** 2026-08-31
**Advisory:** [GHSA-cfcw-xp6x-25gj / CVE-2026-47698](https://github.com/advisories/GHSA-cfcw-xp6x-25gj), critical, CVSS 9.8
**Affected:** `vm2 <= 3.11.5` (patched in `3.11.6`)

Follow-up to the [2026-05-29 vm2 / NodeVM batch](2026-05-29-vm2-nodevm-and-sglang-runtime-boundary-batch-ghsa.md) and the [2026-05-07 vm2 sandbox-escape batch](2026-05-07-vm2-sandbox-escape-boundary-batch-ghsa.md). The fix for [GHSA-v6mx-mf47-r5wg](https://github.com/advisories/GHSA-v6mx-mf47-r5wg) (CVE-2026-47131) is **insufficient and bypassable**: the dangerous-mutator deny-list keys off the *direct* call shape `indirectcall.call(dangerousmutator, ...)`, and swapping the receiver to the indirect-call object itself, `indirectcall.call(indirectcall, dangerousmutator, ...)`, slips through because indirect calls are not classified as dangerous.

## The primitive

Inside a `vm2` VM context the attacker:

1. Reaches `Buffer.call` (the native `Function.prototype.call` exposed via the `Buffer` intrinsic).
2. Lifts `__proto__` getters/setters off any host object via `__lookupGetter__` / `__lookupSetter__`:
   `Buffer.call.call(Buffer.call, {}.__lookupGetter__, Buffer, "__proto__")`.
3. Forces a host-originated exception (`await WebAssembly.compileStreaming()` in a context without that API) and **re-points the exception object's prototype** to the lifted host `__proto__` chain, so `e.constructor.constructor` is `Function`.
4. Executes `e.constructor.constructor("return process")()` and then `.mainModule.require('child_process').execSync(...)` for host RCE.

Confirmed by the advisory's PoC (`touch pwned`). The durable lesson: **a deny-list of "dangerous" host objects is only as strong as the call shapes it recognizes; an attacker who can invoke any of those objects through a *different receiver* (the indirect-call object, a proxy, a lifted intrinsic) bypasses the shape check.**

## Durable operator value

Reusable across any in-process JS sandbox (vm2, RestrictedPython-style guards, WASI wrappers, agent tool executors, CI sandbox plugins):

1. **Classify the guard, not the payload.** Find the exact predicate (e.g. "receiver is the dangerous object" vs "callee is in the deny-list"). Then enumerate receiver-swapping variants: `X.call(X, y, ...)`, `Reflect.apply`, `fn.bind`/`fn.call` via lifted intrinsics, proxy `apply` traps, `Symbol.toPrimitive` coercion paths.
2. **Assume every reachable intrinsic is load-bearing.** `Function.prototype.call`, `__lookupGetter__`/`__lookupSetter__`, `constructor.constructor`, and `WebAssembly` promise/exception channels are the recurring vm2 escape seams (see both May batches). If any one crosses the boundary, the "sandbox" is a suggestion.
3. **Exception objects are bridges.** Host-originated errors that cross into the sandbox retain host `__proto__`/`constructor` chains; re-prototyping the exception is the classic last step. Test whether sandbox code can read `e.constructor.constructor` on a deliberately triggered error.
4. **Version-gate the check.** This bypass works up to `vm2 3.11.5`; `3.11.6` is the first safe release. Record the `vm2` version in any sandbox-boundary report.

## Replayable validation boundaries

- **Preconditions:** an authorized lab host running a product that evaluates user-supplied JavaScript via `vm2 <= 3.11.5` (or a local harness that imports the target's `vm2`/`NodeVM` configuration from its lockfile).
- **Version/config proof first:** capture `vm2` version + `VM`/`NodeVM` options (`require`, `nesting`, `produce`/`consume` proxies) from manifests or container images before touching payloads.
- **Benign host-execution marker only:** in the lab, replace the advisory PoC's `execSync('touch pwned')` with `id`, a canary file in a disposable temp directory, or reading a synthetic environment variable. Positive evidence is the marker, plus the exact receiver-swap line that bypassed the guard.
- **Do not** target production multi-tenant deployments with escape payloads; do not read host secrets, environment files, or cloud credentials; do not leave executed content on the host.
- **Negative control:** run the same payload on `vm2 >= 3.11.6` (or with the feature disabled) and confirm denial, this isolates the deny-list shape check as the differential.

## Reporting heuristics

- Lead with the trust boundary: *user-supplied JS evaluated in-process as a security boundary*, state why in-process isolation is relied upon (tenant code, plugin system, workflow engine, agent tool).
- Include: `vm2` version, Node runtime version, `VM`/`NodeVM` configuration, the exact guard predicate being bypassed, the receiver-swapping line, and the benign marker proof.
- Distinguish **host RCE** from **capability bypass** (network builtins, file writes) as in the May batches.
- Frame the finding as "sandbox deny-list shape bypass," not a generic version finding, the reusable pattern (receiver/callee shape confusion) is what makes it actionable on other products.

## Sources

- [GitHub Advisory Database: vm2 GHSA-cfcw-xp6x-25gj / CVE-2026-47698](https://github.com/advisories/GHSA-cfcw-xp6x-25gj)
- Prior vm2 batches: [2026-05-29 vm2/NodeVM/SGLang](2026-05-29-vm2-nodevm-and-sglang-runtime-boundary-batch-ghsa.md), [2026-05-07 vm2 sandbox-escape batch](2026-05-07-vm2-sandbox-escape-boundary-batch-ghsa.md)
