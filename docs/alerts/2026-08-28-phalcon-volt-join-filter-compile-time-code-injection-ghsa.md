# Phalcon Volt `join` filter compile-time PHP code injection, operator validation

**Date reviewed:** 2026-08-28  
**Advisory:** [GHSA-hrwp-4hh9-c8r8 / CVE-2026-59989](https://github.com/advisories/GHSA-hrwp-4hh9-c8r8), critical  
**Affected:** Phalcon Volt template compiler (`phalcon/Mvc/View/Engine/Volt/Compiler`); confirmed against Phalcon 5.15.0 generated C output  
**Boundary class:** template filter argument bytes concatenated unescaped into generated PHP, then compiled to a cache file and `require()`d at render, compile-time code injection / SSTI → RCE.

## The primitive

Volt compiles templates to PHP and caches the result, which the view engine `require()`s on every render. Most filter arguments are routed through the compiler's `expression()` helper, which quotes/escapes them before they are spliced into generated code. The `join` filter is the exception: the compiler emits the separator literal and the piped array argument **as raw template-token bytes, with no escaping**:

```zephir
case "join":
    return "join('" . funcArguments[1]["expr"]["value"]
        . "', " . funcArguments[0]["expr"]["value"] . ")";
```

- `funcArguments[1]` (the separator string) is dropped verbatim between two single quotes the compiler emits. A `'` in the separator breaks out of the generated string literal.
- `funcArguments[0]` (the piped array) is emitted completely bare, so it can carry arbitrary PHP.
- Volt's scanner stores string-literal bytes verbatim (escape sequences are not decoded), so attacker bytes survive into the generated PHP intact.

The confirmed generated C (`build/phalcon/phalcon.zep.c`, Phalcon 5.15.0) is literally `ZEPHIR_CONCAT_SVSVS(return_value, "join('", separator, "', ", array, ")");`, both attacker fragments unescaped.

The result: any application that compiles attacker-influenced Volt source gets **server-side template injection that executes as PHP at render time** in the web-server process.

## Replayable validation (lab only)

Preconditions: a lab Phalcon app with the Volt engine, a source template whose `join` arguments you control (or an admin-authored template reachable via user data), and a patched/denied process sink. Do not execute commands on production; the strongest acceptable evidence is a canary echo.

1. **Confirm the unescaped path.** Compile a template that puts a marker in both `join` arguments:

   ```
   {{ ['x'] | join("SEPARATOR", ['a','b']) }}
   ```

   Inspect the generated PHP (Volt's cache dir or `Compiler::compileString` in a harness). A vulnerable compiler emits the separator **inside** the single-quoted string and the array **unquoted**, while sibling filters (e.g. `uppercase`, `capitalize`) emit quoted/escaped forms. That differential is the positive.

2. **Break the literal without executing.** Craft the separator to close the string and comment out the rest, then echo a canary:

   ```
   {{ ['x'] | join("', []); echo 'CANARY-7f3a; //", ['a']) }}
   ```

   If the rendered output contains the literal canary (and the raw template bytes never appeared in output on the patched build), the injection boundary is proven. This is the stop point for most programs.

3. **Bound the execution claim.** The advisory's PoC base64-decodes a command into `shell_exec`. In an authorized lab with a denied process sink, replace `shell_exec` with a recorder that only logs the argument and returns a fixed string; record the recorded argument as evidence. Never run discovery, persistence, or network commands outside the lab boundary.

## Recon heuristics

- Look for Volt templates (or any template engine with a compiler step) where template source mixes trusted layout with user input: page-builder fields, user-authored snippets, admin "custom template" editors, CMS theme fields.
- The dangerous transition is **compile-time**, not render-time: WAFs and output filters that only inspect final HTML do not see the injected PHP, and the compiled cache file persists between requests. Check whether the compiled template cache is readable/writable or versioned, a poisoned cache file is durable even after the input is gone.
- When auditing template compiler code, enumerate every filter/loop/block case and check each one for the quote-or-escape differential. One unescaped argument in one case is enough; the `join` case is the confirmed instance, but the audit pattern applies to any sibling case that interpolates a raw token value.

## Safe boundaries

- Authorized targets only, lab Phalcon deployment or a harness around `Compiler::compileString`.
- Canary markers only; no command execution, no cache-file writes outside the test cache dir, no production template modifications.
- Report the exact generated-PHP line, the affected Phalcon build, and the input-to-compile-to-render path with the patched-build negative control.

## Sources

- [GitHub Advisory Database: Phalcon Volt GHSA-hrwp-4hh9-c8r8 / CVE-2026-59989](https://github.com/advisories/GHSA-hrwp-4hh9-c8r8)
