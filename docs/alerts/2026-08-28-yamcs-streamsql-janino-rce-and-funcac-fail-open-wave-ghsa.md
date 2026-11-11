# Yamcs StreamSQL Janino RCE, missing function-AC wave, and Phalcon router ReDoS, operator validation

**Date reviewed:** 2026-08-28
**Primary advisory:** [GHSA-3g44-3m7x-cgg2 / CVE-2026-55511](https://github.com/advisories/GHSA-3g44-3m7x-cgg2), critical, 9.1, authenticated RCE
**Boundary class:** expression-compiler code injection (generated Java from a user-controlled identifier) plus a batch of controllers that execute business logic without the framework's own privilege checks.

## The primitive: StreamSQL column-name → generated Java

Yamcs compiles StreamSQL expressions to Java on the fly with Janino `SimpleCompiler`, no restrictive class-loading policy, no API allowlist. When an aggregate such as `sum(...)` is applied to a **plain column**, the column's *name* is interpolated **unescaped** into the generated Java source:

```java
// SumExpression#aggregateFillCode_newData
code.append("\t\tsum+=col" + children[0].getColumnName());
```

`sanitizeName()` maps only `/` and `-` to `_`. Every other character, `;`, spaces, `(`, `)`, `{`, `}`, `=`, `.`, `,`, digits, passes through verbatim. The grammar accepts any character except newline / CR / double-quote inside a double-quoted identifier, and neither `ColumnDefinition` nor `TupleDefinition` validates the characters of a column name. So `CREATE TABLE t("<arbitrary text>" double, ...)` creates a column whose name is attacker-chosen text.

Why the **aggregate** path is exploitable while the bare-expression path is not: in `SumExpression`, both emissions of the column name live inside `newData(Tuple tuple)`, a `void` statement-context method, and `getValue()` returns the accumulator `sum`, never the column. A `;`-separated, fully reachable payload compiles cleanly, while the bare path hits "Statement is unreachable". `executeSql` with a plain-column aggregate additionally **skips** the bare `Expression#compile()` gate (`aggInputList = null` when no computed arguments), going straight to `getCompiledAggregate()`.

Reachability: `POST /api/archive/{instance}:executeSql` → `TableApi.executeSql`, gated by `SystemPrivilege.ControlArchiving`, **not** superuser and **not** `ChangeMissionDatabase`. This is a second, independent Janino-RCE entry point sharing the root cause of CVE-2026-44632 (`GHSA-524g-x36v-9wm6`); the 5.13.0/5.12.7 fix for that CVE hardened only the algorithm-override path and left the StreamSQL compiler exploitable.

The advisory's PoC was verified end-to-end against a security-enabled Yamcs 5.13.0: a non-superuser holding only `ControlArchiving` executed a benign `java.io.File(...).mkdirs()` marker on the host via a malicious column name, while a privilege-less user got `403 ForbiddenException "Missing system privilege 'ControlArchiving'"` at the same gate.

## Replayable validation (lab only)

Preconditions: a lab Yamcs deployment with security enabled, an account holding **only** `SystemPrivilege.ControlArchiving`, a second no-privilege control account, and a read path to confirm a marker directory. Do not execute commands on production; the strongest acceptable evidence is a marker directory.

1. **Confirm the privilege gate.** As the no-privilege control user, POST a trivial statement to `:executeSql` and record the 403 with the missing-privilege message. This is your negative control.
2. **Confirm the unescaped path.** As the `ControlArchiving` user:
   - `create table <uniq>(\"<marker-laden column name>\" double, id int, primary key(id))`, the malicious name must be accepted (HTTP 200).
   - `insert into <uniq>(id, \"<col>\") values(1, 1.0)`
   - `select sum(\"<col>\") from <uniq>`, this compiles the aggregate and runs `newData()` per row.
3. **Build the payload without `"` or `/` in the column name.** The column name is emitted inside Java string context too, so construct file paths from char codes: `dummy; new java.io.File(new String(new char[]{...})).mkdirs(); coldummy=coldummy`. The trailing `coldummy=coldummy` is a valid statement in both emission positions, which is what keeps the generated `newData()` compiling.
4. **Stop at the marker.** The marker directory on the host proves arbitrary Java execution in the Yamcs JVM. Do not escalate to OS commands, credential access, or lateral movement outside the authorized scope.

## Recon heuristics

- **Expression-to-code compilers are a class, not an instance.** Any product that generates source (Java, Python, C) from user identifiers and compiles it on the fly is a candidate. Enumerate every emission context, identifier position, string literal, value literal, and check which one escapes. One unescaped identifier context with a `void`/statement sink is usually enough.
- **Second-primitive hunting after a patch.** When a vendor fixes a code-injection path by hardening one compiler or one gate (here: `JavaExprAlgorithmExecutionFactory` behind `ChangeMissionDatabase`), enumerate sibling compilers and sibling privileges reaching the same sink class. The 5.13.0 fix for CVE-2026-44632 left this entry point open via `ControlArchiving`.
- **Privilege-differential evidence.** Capture the exact gate: which privilege succeeds, which fails, and the error body. `ControlArchiving` (archive/table/stream management) is the low-privilege handle that matters, report it precisely, not "an authenticated user".

## Same-root follow-on RCEs and the unauthenticated traversal (same product, same wave)

The aggregate-compiler column-name injection above is one of several independent Janino-RCE entry points disclosed in the same Yamcs wave. Treat the whole compiler surface as a single primitive class and test each emission context.

### 1. Unescaped StreamSQL `LIKE` pattern compiled by Janino, RCE at read-only privileges

[GHSA-c64q-hj4j-375f / CVE-2026-55565](https://github.com/advisories/GHSA-c64q-hj4j-375f), critical. `LikeExpression#fillCode_getValueReturn` appends the user-supplied LIKE pattern **raw** into `Utils.like(<col>, "<pattern>")`, a `"..."` literal in the generated Java. A pattern containing `"` breaks out and injects arbitrary Java (e.g. a `static{}` block that runs on class load). Because the pattern is embedded whether it comes from a SQL literal or a bound `?` argument, the sink is reachable from **any** endpoint that builds a `LIKE` from user input, at routine **read-only** privileges, lower than the `ControlArchiving` gate of the aggregate path:

- `POST /api/archive/{instance}/tables/{table}:readRows` `query` field, privilege `ReadTables`
- `GET /api/archive/{instance}/events?q=` and event export/stream variants, privilege `ReadEvents`
- `listActivities` `q`, privilege `ReadActivities`
- The web Events page search box feeds `q` directly.

Independent of the May-2026 algorithm-override RCEs (CVE-2026-46562/46621/44632): needs none of `ChangeMissionDatabase` and is not behind the `overrideAlgorithmsEnabled` gate. Sink: `Expression#getCompiledExpression` compiles with `SimpleCompiler.cook(...)` and instantiates at stream prep, before any tuple flows.

Replayable validation: as a `ReadEvents`-only account, send `GET /api/archive/{instance}/events?q=` with a pattern that breaks out of the `"` literal into a benign `java.io.File(...).mkdirs()` marker; the positive is the marker on the host plus the generated-Java context. Use a read-only control account and stop at the marker, no OS commands, no archive tampering.

### 2. Instance-template argument YAML injection, `createInstance` RCE, default-guest reachable

[GHSA-73mf-m39p-wpm9 / CVE-2026-55559](https://github.com/advisories/GHSA-73mf-m39p-wpm9), critical. `templateArgs` sent to `POST /api/instances` (and `PATCH /api/instances/{instance}`) are written into the rendered instance config **as raw text**, then parsed as YAML and loaded. `VarStatement` appends arg values with no escaping; the only filter (`EscapeFilter`) does HTML escaping and leaves newlines, colons, and indentation alone, so `{{ x | escape }}` does not help. Because Yamcs instantiates each `services:` entry by its `class:`, injecting YAML through a template arg lets you add a `services:` entry for `org.yamcs.ProcessRunner` and run a command on the host.

The durable pattern: **template args are not escaped for the target format (YAML), and the rendered config is not re-validated against the declared variables, `choices`/`required` metadata is only used to render the web form.** `InstancesApi.createInstance` checks `CreateInstances` but forwards args without content checks. With no `security.yaml` the `guest` user is `superuser=true` and the API is unauthenticated, so the default exposure is unauthenticated RCE, same default posture as CVE-2026-46562. The 5.12.7 algorithm-edit fix does not touch this path.

Replayable validation: lab instance, a `CreateInstances` account (or default guest), a template arg whose value is a YAML `services:` block that instantiates a benign marker class (not `ProcessRunner`). Positive: the instance boots with the injected service and a marker side effect. Report the exact arg-to-YAML-to-`services:` path and the default-guest posture.

### 3. Unauthenticated directory traversal, arbitrary file read

[GHSA-9jg3-g3wh-w9pj / CVE-2026-55552](https://github.com/advisories/GHSA-9jg3-g3wh-w9pj), high, Yamcs `<= 5.8.6`, `HttpRequestHandler` / `StaticFileHandler`. A request such as `http://<host>:8090//etc/passwd` (double-slash then absolute path) is served without root confinement, so an unauthenticated remote attacker downloads arbitrary host files. This is the lowest-friction entry point in the wave and the one most likely to be hit by scanners.

Replayable validation: confirm the affected version, then request a **non-sensitive** marker file you placed outside the web root (e.g. `//<canary-dir>/canary.txt`) and record the 200 with the marker body. Do not read `/etc/passwd`, credentials, or cloud tokens in production; the marker proof is sufficient. Report the version, the exact request, and the resolved path.

### 4. DOM XSS in extension routing (lower priority)

[GHSA-9272-wg2r-7xmx / CVE-2026-55566](https://github.com/advisories/GHSA-9272-wg2r-7xmx), medium, unauthenticated. The `/ext` route reflects URL fragments into a custom-element `innerHTML` path; `http://<host>/ext/img%20src%3Dx%20onerror%3Dalert%281%29?c=<instance>` executes in the victim's browser. Durable as a standard reflected/DOM-XSS probe against the `/ext` surface; report with an inert `alert(1)` canary, no data exfiltration.

## Same-product fail-open batch

The same Yamcs wave carries three controllers that execute business logic **without** the RBAC checks the rest of the API applies. These are the "missing function-level access control" pattern: a controller reached by any authenticated user performs an action that requires a system privilege the code never asserts.

| Advisory | Gap | Operator value |
| --- | --- | --- |
| [GHSA-962x-ccwf-8x6p / CVE-2026-55521](https://github.com/advisories/GHSA-962x-ccwf-8x6p) | `IndexesApi` (packet/event index reads), `Cop1Api` (telecommand link state), `TimeApi` (global simulation time) omit `checkSystemPrivilege` / object-privilege checks | With a low-privilege account, replay each endpoint and compare against a privileged control; evidence is the accepted mutation/response where a sibling controller requires `ControlLinks` or `ReadPacket`. |
| [GHSA-fwww-cp23-7f5g / CVE-2026-55545](https://github.com/advisories/GHSA-fwww-cp23-7f5g) | WebSocket subscription handlers omit the privilege checks their REST equivalents perform | Audit the WS subscribe/unsubscribe handlers against their REST twins; a subscribed stream that the REST `GET` denies is the positive. |
| [GHSA-8xjq-pr36-ccgf / CVE-2026-55548](https://github.com/advisories/GHSA-8xjq-pr36-ccgf) | `PacketsApi` IDOR, packet reads not filtered by object privilege in the reported path | Test packet reads with a low-privilege user against a foreign packet ID; capture the read decision, not just the status. |
| [GHSA-cvw4-55pp-3hfq / CVE-2026-55547](https://github.com/advisories/GHSA-cvw4-55pp-3hfq) | Role and privilege enumeration endpoints lack authorization | A low-privilege user enumerating all roles/privileges is the positive; report the enumeration response shape. |
| [GHSA-rxpg-wjf8-qv9c / CVE-2026-55549](https://github.com/advisories/GHSA-rxpg-wjf8-qv9c) | Reflected XSS in the Authorize endpoint URL | Standard reflected-XSS validation; lower priority next to the AC/RCE items. |

Validation for the AC batch: use two synthetic accounts (low-privilege vs. properly-privileged), replay each endpoint against synthetic data, and record the accept/deny differential with the exact privilege that should have gated it. No telemetry export, no link-state changes, no simulation-time changes outside the lab.

## Related Phalcon findings

The Phalcon SSTI→RCE item is published as a standalone page: [Phalcon Volt `join` filter compile-time PHP code injection (GHSA-hrwp-4hh9-c8r8 / CVE-2026-59989)](2026-08-28-phalcon-volt-join-filter-compile-time-code-injection-ghsa.md). Two further Phalcon items were reviewed without a standalone page:

- [GHSA-x7rj-f32v-7jjg / CVE-2026-57584](https://github.com/advisories/GHSA-x7rj-f32v-7jjg): catastrophic backtracking in the default Phalcon `Mvc\Router` compiled pattern `#^/([\w0-9\_\-]+)/([\w0-9\.]+)(/.*)*$#u`, the trailing `(/.*)*` nested quantifier makes a request URI of ~N slashes cost ~2^(N/2) engine steps. `Router::handle()` runs on every request, so a single short request burns CPU pre-auth. Durable recon heuristic: any router/regex library that compiles user-influenced route patterns is a ReDoS probe target; the `/:params` placeholder generates the same construct.
- [GHSA-8jqh-95g6-7jpj / CVE-2026-54736](https://github.com/advisories/GHSA-8jqh-95g6-7jpj): non-constant-time HMAC verification in `Phalcon\Encryption\Crypt::decrypt` (`!==` lowered to a byte-wise `memcmp`), the one deviation from `hash_equals()` in the framework. Weak signal: MAC-verification timing side-channel is hard to exploit remotely and the advisory itself frames it as a side-channel note; tracked here as an audit pattern (MAC-comparison consistency across a framework) rather than an operator workflow.

## Safe boundaries

- Authorized targets only, lab Yamcs deployment with security enabled and the exact low-privilege account per entry point (`ControlArchiving`, `ReadEvents`, `CreateInstances`, or no-auth for the traversal).
- Marker directory / marker file / marker service only; no OS commands, no credential access, no archive tampering, no link-state or simulation-time changes, no real-host file reads.
- Report the exact privilege gate (or unauthenticated posture), the generated-Java / YAML / path context, and the input-to-compile-to-execute path with the denied negative control.

## Sources

- [GitHub Advisory Database: Yamcs GHSA-3g44-3m7x-cgg2 / CVE-2026-55511](https://github.com/advisories/GHSA-3g44-3m7x-cgg2)
- [GitHub Advisory Database: Yamcs GHSA-c64q-hj4j-375f / CVE-2026-55565](https://github.com/advisories/GHSA-c64q-hj4j-375f)
- [GitHub Advisory Database: Yamcs GHSA-73mf-m39p-wpm9 / CVE-2026-55559](https://github.com/advisories/GHSA-73mf-m39p-wpm9)
- [GitHub Advisory Database: Yamcs GHSA-9jg3-g3wh-w9pj / CVE-2026-55552](https://github.com/advisories/GHSA-9jg3-g3wh-w9pj)
- [GitHub Advisory Database: Yamcs GHSA-9272-wg2r-7xmx / CVE-2026-55566](https://github.com/advisories/GHSA-9272-wg2r-7xmx)
- [GitHub Advisory Database: Yamcs GHSA-962x-ccwf-8x6p / CVE-2026-55521](https://github.com/advisories/GHSA-962x-ccwf-8x6p)
- [GitHub Advisory Database: Yamcs GHSA-fwww-cp23-7f5g / CVE-2026-55545](https://github.com/advisories/GHSA-fwww-cp23-7f5g)
- [GitHub Advisory Database: Yamcs GHSA-8xjq-pr36-ccgf / CVE-2026-55548](https://github.com/advisories/GHSA-8xjq-pr36-ccgf)
- [GitHub Advisory Database: Yamcs GHSA-cvw4-55pp-3hfq / CVE-2026-55547](https://github.com/advisories/GHSA-cvw4-55pp-3hfq)
- [GitHub Advisory Database: Yamcs GHSA-rxpg-wjf8-qv9c / CVE-2026-55549](https://github.com/advisories/GHSA-rxpg-wjf8-qv9c)
- [GitHub Advisory Database: Phalcon GHSA-x7rj-f32v-7jjg / CVE-2026-57584](https://github.com/advisories/GHSA-x7rj-f32v-7jjg)
- [GitHub Advisory Database: Phalcon GHSA-8jqh-95g6-7jpj / CVE-2026-54736](https://github.com/advisories/GHSA-8jqh-95g6-7jpj)
