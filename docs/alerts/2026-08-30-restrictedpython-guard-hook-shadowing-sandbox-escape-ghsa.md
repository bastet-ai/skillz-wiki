# RestrictedPython guard-hook shadowing via positional-only arguments — sandbox-escape operator validation

**Date reviewed:** 2026-08-30
**Advisory:** [GHSA-ffg3-p8fm-mjx2 / CVE-2026-55830](https://github.com/advisories/GHSA-ffg3-p8fm-mjx2) — high, CVSS 8.3
**Affected:** `RestrictedPython <= 8.2` (pip); fixed in `8.3`

## The primitive

RestrictedPython rewrites sensitive operations in sandboxed Python to go through **guard hooks** supplied by the embedding application:

- Attribute access → `_getattr_(obj, name)`
- Item access → `_getitem_(obj, key)`
- Write → `_write_(value)`
- Print → `_print_(value)`

The embedding application is expected to supply these hooks to enforce its access policy. Argument-name validation in RestrictedPython rejects these protected names for **regular arguments**, `*args`, `**kwargs`, and **keyword-only** arguments — but **misses positional-only arguments** (those before `/` in the signature).

```python
def f(_getattr_=evil, /):
    return o.x
```

Because `_getattr_` is now a **local variable** that shadows the policy hook, the rewritten `o.x` access calls `evil` instead of the embedding application's `_getattr_`. The same shadowing works for `_getitem_`, `_write_`, and `_print_`. Shadowing `_print_` can also capture the internal `_getattr_` hook that RestrictedPython passes in internally.

## Why this is durable

The bug class is **naming-collision between a sandbox's internal protocol names and a user-facing language feature**. Any sandbox that rewrites code to route through named hooks (guard functions, policy callbacks, interceptor methods) must validate that user-supplied code cannot **shadow those names as locals**. Positional-only parameters are the least obvious vector because:

1. They are syntactically distinct from keyword arguments (most name-collision checks target the keyword path).
2. They bind to a local scope visible to the rewritten code.
3. Python's function definition grammar allows them to precede `/` without any annotation that a linter or sandbox author would flag.

Reusable across any Python sandbox, policy engine, or code-rewrite framework that uses named hooks or policy callbacks:

- **Enumerate the hook names** the sandbox rewrites to (`_getattr_`, `_getitem_`, `_write_`, `_print_`, or equivalent).
- **Test every argument-binding path** (regular, `*args`, `**kwargs`, keyword-only, positional-only) for shadowing.
- **Check whether the sandbox uses the hook name as a local or global** that user code can override.

## Replayable validation (lab only)

Preconditions: a local Python environment with `RestrictedPython <= 8.2` installed, a disposable policy hook that logs or denies access, and a synthetic sandboxed code snippet. No production embedding application, no real user data, no network access from the sandboxed code.

1. **Baseline.** Run a simple `o.x` access through the sandbox with the embedding application's normal `_getattr_` hook. Confirm the hook is called.
2. **Shadow test.** Define a function with `_getattr_=evil_marker, /` where `evil_marker` writes to a marker file or logs a canary string. Run `o.x` inside that function. The positive is that `evil_marker` is called instead of the real `_getattr_`.
3. **Capture the internal hook.** Shadow `_print_` and inspect whether the internal `_getattr_` hook object is accessible in the shadowed scope. This is the highest-value capture because it exposes the embedding application's policy internals.
4. **Chain check.** If the embedding application serializes sandbox-controlled objects (e.g. via `pickle`), test whether the shadowed hook can be used to control the serialization path. Stop at the hook-shadowing proof; do not execute untrusted pickle payloads.
5. **Negative control.** Re-run the same test on `RestrictedPython 8.3+` and confirm the positional-only shadowing is rejected.

Stop at "guard hook was shadowed and the policy callback was bypassed." Do not attempt to read real files, access network resources, or execute shell commands from the sandbox.

## Reporting heuristic

- Lead with the **hook-name → positional-only local** transition. Name the exact hook, the exact argument position, and the embedding application's policy that was bypassed.
- Include the `RestrictedPython` version, the Python version, the exact function signature that triggers the shadow, and the observed policy bypass.
- Distinguish the shadowing primitive from any downstream exploitation (pickle RCE, file read, etc.). The shadowing is the finding; downstream impact is context.
- Do not publish a weaponized payload. The proof is the shadow + the bypassed policy callback.

## Safe boundaries

- Local Python environment with `RestrictedPython <= 8.2` only. No production embedding application.
- Synthetic sandboxed code and synthetic policy hooks only. No real user data, no network access, no file access outside the test directory.
- Stop at the hook-shadowing proof. Do not chain into pickle deserialization, file I/O, or shell execution.

## Follow-up: second escape axis — `string.Formatter` internal traversal (2026-09-17)

[GHSA-hp3v-5vw7-fx9w](https://github.com/advisories/GHSA-hp3v-5vw7-fx9w) (published 2026-09-17T16:30Z) is a **distinct escape mechanism** in the same product: when the embedding policy exposes the stdlib `string` module or a `Formatter` instance, `string.Formatter.get_field` performs attribute/item traversal **internally**, returning live object references without ever routing through `safer_getattr`. Shadowing the guard hook is unnecessary — the traversal never enters the guard. Full write-up, harness, and the Zope AccessControl `str.format`/`format_map` + str-subclass sibling: [Sept 17 policy-sandbox traversal page](2026-09-17-python-policy-sandbox-traversal-umbraco-reference-expansion-and-mariadb-local-infile-ghsa.md). Combined audit rule: test both **name-shadowing of the guard** and **stdlib functions that traverse without calling the guard**.

## Sources

- [GitHub Advisory Database: RestrictedPython GHSA-ffg3-p8fm-mjx2 / CVE-2026-55830](https://github.com/advisories/GHSA-ffg3-p8fm-mjx2)
- [NVD: CVE-2026-55830](https://nvd.nist.gov/vuln/detail/CVE-2026-55830)
- [Fix commit](https://github.com/zopefoundation/RestrictedPython/commit/3737596ec9f28c34a073cc845bd2f4c0a80cb671)
