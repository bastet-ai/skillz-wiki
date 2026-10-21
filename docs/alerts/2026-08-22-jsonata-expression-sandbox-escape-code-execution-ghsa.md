---
title: JSONata expression sandbox escape and arbitrary-code-execution boundaries
---

# JSONata expression sandbox escape and arbitrary-code-execution boundaries

Three critical GitHub Security Advisories published 2026-08-21 describe the same durable pattern in the **JSONata** JavaScript expression library: a language that is *supposed* to be a safe, data-only query/transform layer can be escalated to arbitrary host code execution when the evaluator's built-in environment is not hermetic. All three land in **CWE-94 (Code Injection)** and are fixed in `jsonata` `2.2.1` (2.x line) and `1.8.8` (1.x line). The reusable operator insight: **a "safe" expression/query language is only as safe as the lookup, clone, and function-call primitives its evaluator exposes to the expression**. If any of those primitives can reach `Object.prototype`, `Function`, or `constructor`, the data layer is an RCE layer.

Source records:

- prototype-pollution → constructor-escape via `__lookupSetter__('__proto__')` in the `lookup` function (missing `hasOwnProperty` check): [GHSA-8gq3-vp5j-2grp / CVE-2026-77413](https://github.com/advisories/GHSA-8gq3-vp5j-2grp);
- bypassable `hasOwnProperty` check in `environment.lookup` allowing `$spread($string)` to reach `process.getBuiltinModule`: [GHSA-2943-5xfg-gq5f / CVE-2026-77414](https://github.com/advisories/GHSA-2943-5xfg-gq5f);
- `$clone` overwrite + destructing JSONata functions/lambdas (`$merge.*`) + `proc.arguments.forEach` instead of `Array.prototype.forEach` in `applyProcedure`, chained to execution: [GHSA-66mm-25pp-rfff / CVE-2026-77415](https://github.com/advisories/GHSA-66mm-25pp-rfff).

Confirm the exact `jsonata` version, whether the evaluator runs in a **server-side** context with `process` available (Node.js), and whether user-controlled expressions reach the evaluator (search/transform UIs, ETL pipelines, workflow engines, query layers, report builders) before testing.

!!! warning "Lab-only, no live host command execution, inert sinks"
    Use a disposable Node.js host with the affected `jsonata` version pinned. Patch the final execution sink (`process.getBuiltinModule`, `child_process.execSync`, `Function`) with a denied recorder that captures the expression and rejects before any real command runs. Never point a real JSONata evaluator at an operator-controlled expression in production, and never execute a real shell command to prove the boundary.

## Boundary map

| Surface | Intended authority | Untrusted input | Bounded positive |
| --- | --- | --- | --- |
| `lookup` (functions.js) | data-only member access on the bound context | expression that reaches `__proto__` via `__lookupSetter__` | `__lookupSetter__('__proto__')` resolves `constructor` instead of a data property |
| `environment.lookup` | hermetic built-in resolution | `$spread($string)` + `$constructor` | `hasOwnProperty` check bypassed; `$constructor` reaches a callable |
| `evaluateTransformExpression` / `$clone` | non-mutating transform | overridden `$clone` returning a value verbatim | object mutation via transforms where the evaluator should treat inputs as read-only |
| `applyProcedure` | function application via `Array.prototype.forEach` | `proc.arguments.forEach` (instance method) | per-call-site `forEach` instead of the frozen prototype method |
| `constructor` → `Function` | no arbitrary code from data expressions | crafted expression returning a `Function`/`execSync` | denied recorder captures a `process.getBuiltinModule('child_process')` invocation attempt |

The finding is the **broken binding between "expression" and "evaluator environment"**, not the JSONata result string. Capture the expression, the primitive that leaked the prototype/constructor, and the denied-sink record separately.

## 1. `lookup` prototype-pollution to constructor escape

`GHSA-8gq3-vp5j-2grp` (CVE-2026-77413) is the first record: the `lookup` function in `functions.js` performs a property read without a `hasOwnProperty` guard, so an expression can walk `__proto__` and resolve an inherited callable. The published PoC chains `__lookupSetter__('__proto__')(constructor)` into a getter that returns `child_process.execSync` output.

Replayable validation:

1. Pin `jsonata` to the affected version (`< 2.2.0` on the 2.x line, `< 1.8.8` on the 1.x line) in an isolated Node.js host with no outbound network.
2. Patch `child_process.execSync` / `Function` / `process.getBuiltinModule` with a recorder that captures its arguments and **throws / returns a fixed inert value** instead of executing.
3. Evaluate the published-style expression (the one that builds a getter returning the `execSync` result) through `jsonata(expr).evaluate({})`.
4. Confirm the recorder observed the target call on the affected build and **did not** on the patched build.
5. Record the exact primitive (`__lookupSetter__`, `__proto__`, `constructor`) that carried the leak.

A bounded positive is **data expression → `lookup` → `__proto__`/`constructor` reachable → denied recorder observes an execution-sink argument**, on the affected build only. Report the version, the specific primitive chain, and the recorder capture. Do not claim host command execution without the recorder; a real `execSync` run is out of scope.

## 2. `environment.lookup` `hasOwnProperty` bypass

`GHSA-2943-5xfg-gq5f` (CVE-2026-77414) is the second record: a `hasOwnProperty` check in `environment.lookup` is bypassable, so `$spread($string)` can reconstruct a callable and reach `process.getBuiltinModule`. The published PoC builds `Function("return process.getBuiltinModule('child_process').execSync('sh',{stdio:'inherit'})")()`.

Replayable validation:

1. Same pinned-host setup as section 1.
2. Recorder-patch the `Function` constructor and `process.getBuiltinModule` so any call is captured and denied.
3. Evaluate the published-style expression that sets `$hasOwnProperty := $spread($string)` then `$constructor("return process.getBuiltinModule(...)")()`.
4. Confirm the recorder fires on the affected build and not on the patched build.

A bounded positive is **`$spread`/`$constructor` chain → `environment.lookup` guard bypass → denied recorder observes `process.getBuiltinModule`/`Function`**. Do not open a real shell; the proof is the recorder.

## 3. `$clone` overwrite, lambda destruct, and `forEach` per-call-site

`GHSA-66mm-25pp-rfff` (CVE-2026-77415) is the third record and the most layered: it combines (a) overwriting `$clone` so transforms mutate inputs the evaluator treats as read-only, (b) destructing JSONata functions/lambdas (`$merge.*`), and (c) `applyProcedure` calling `proc.arguments.forEach` (the per-object method) rather than `Array.prototype.forEach`. Chained, these reach arbitrary code.

Replayable validation:

1. Pinned affected host; recorder-patch `child_process.execSync` and any `Function`/`constructor` sink.
2. Evaluate the published-style expression that defines `$clone := function($o){ $o }`, destructs `$merge`, and drives `__lookupGetter__`/`__lookupSetter__` against a bound object.
3. Confirm the recorder observes the execution sink on the affected build only.

A bounded positive is **`$clone` overwrite + lambda destruct + `proc.arguments.forEach` → execution-sink argument captured by the recorder**. This record is the clearest statement of the pattern: when an evaluator hands its internal function/argument objects back to the expression, the data layer stops being data-only.

## Reporting heuristics

Lead with the crossed primitive, not the version:

- **`lookup` → `__proto__`/`__lookupSetter__` → inherited `constructor` reachable from data**
- **`environment.lookup` → bypassable `hasOwnProperty` → `process.getBuiltinModule` / `Function`**
- **`$clone` overwrite + lambda destruct + `proc.arguments.forEach` → internal function/argument objects leak to the expression**

Strong reports include the exact `jsonata` version, the evaluator runtime (Node.js vs browser — `process.getBuiltinModule` only matters server-side), the user-input path that reaches `evaluate()`, the specific primitive that leaked the prototype/constructor, the denied-sink capture, and the fixed-build negative control. Note explicitly whether the expression input is attacker-controlled in the target system; a library CVE without a reachable user-input path is a dependency finding, not an operator exploit path.

## Notes on skipped adjacent items

The same 2026-08-21 scan reviewed the Xinference Llama3 tool-call `eval()` RCE (published as a separate page), a GeoTools `jsonArrayContains` unauthenticated SQLi, and a large VulDB-style WordPress/TRENDnet/Joomla/Linux-kernel wave. GeoTools and the product-specific records are tracked to state without publication — they are product/DB-boundary records without a new reusable operator pattern in this window.

## October 21 follow-up: OGNL stricter-invocation block list bypassed via reflection proxies — the denylist sees the call site, not the callee

[GHSA-crwc-vw2r-qr6m / CVE-2026-113730](https://github.com/advisories/GHSA-crwc-vw2r-qr6m) (ognl:ognl ≤3.4.12 → 3.4.13): OGNL's optional stricter-invocation mode blocks `Runtime`, `ProcessBuilder`, `ClassLoader` by filtering on the **declaring class of the method OGNL is asked to invoke**. `java.lang.reflect.Method`/`Constructor`/`Field` are not on the list, so `#methods=@java.lang.ProcessBuilder@class.getMethods(); #methods[#startIdx].invoke(#pb, null)` passes the gate — the real `ProcessBuilder.start()` executes *inside the JDK reflection machinery* and never re-enters OGNL's `invokeMethod`, so the block list never sees it. The advisory is candid that this is defense-in-depth bypass, not primary-boundary break: the primary gate is the integrator's `MemberAccess` (Struts' `SecurityMemberAccess` excludes `java.lang.reflect` and kills the PoC at the constructor).

Operator value for any expression/evaluator product (Struts, iBATIS, any OGNL/SpEL/JEXL/JSONata embed):
- **Denylist-by-declaring-class at a single dispatch point is proxy-bypassable by design** — reflection, dynamic proxies, method handles, lambda metafactories, and scripting bridges all execute the dangerous callee *below* the filter. Audit question: "what does the denylist actually observe — the ultimate callee or the first hop?" Grep the block list for the reflection/`invoke`/`Proxy`/`MethodHandle` family; absence is the fingerprint.
- **Test the layer the integrator is supposed to control too**: with stricter-invocation ON and default `MemberAccess` (all public members), this bypass is the difference between blocked and reachable. When assessing a framework that embeds an expression language, check *which* `MemberAccess`/resolver the framework actually installs — vendor defaults vary per release, and "library has a hardening mode" ≠ "hardening mode is enabled."
- Probe shape stays lab-only per this page's warning: inert marker payloads (`touch` in a temp dir), pinned affected build, denied execution sink recorder, fixed-build negative control.
