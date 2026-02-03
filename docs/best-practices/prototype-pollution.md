# Prototype pollution: defensive guidance (JavaScript)

Prototype pollution bugs happen when attacker-controlled keys can write into an object’s prototype chain (e.g. `__proto__`, `constructor.prototype`). Impact ranges from weird app behavior to auth bypasses and, in some cases, RCE depending on downstream “sinks”.

## When to worry

Treat as **high risk** when you have any of the following:

- You accept **untrusted JSON** and then:
  - deep-merge it into config/state objects
  - apply it as patch/update operations
  - use it to construct options passed to security-sensitive libraries
- You use “dot-path” setters (e.g. `a.b.c`) on untrusted input.
- You use utility libraries that historically had prototype pollution issues (deep merge / deep set / querystring parsing).

## Practical prevention checklist

### 1) Block dangerous keys everywhere you accept object paths

If you accept arbitrary keys (or dot-paths), reject any segment equal to:

- `__proto__`
- `prototype`
- `constructor`

Also consider blocking `toString`, `valueOf`, `__defineGetter__`, `__defineSetter__` in high-risk contexts.

### 2) Avoid deep-merging untrusted objects

Prefer explicit allowlists:

- Parse input → validate schema → copy only known fields
- If you must merge, merge into a **fresh object** with a **null prototype** (see below)

### 3) Use null-prototype maps for “dictionary” objects

For key/value maps populated from untrusted data:

```js
const dict = Object.create(null);
```

This prevents inherited properties from being interpreted as user data.

### 4) Use schema validation, not “best effort” sanitization

Use a schema validator (e.g., Zod/Ajv/Joi) and require:

- `additionalProperties: false` where possible
- types and bounds on values
- explicit key allowlists for records/dicts

### 5) Treat library patches as insufficient unless tests prove it

Some fixes can be bypassed by **monkeypatching built-ins** (e.g., `Object.prototype.hasOwnProperty`, `String.prototype.indexOf`, `String.prototype.includes`) in hostile environments.

This shows up in real-world prototype pollution advisories: a library may “block” keys by checking for forbidden substrings, but if an attacker can influence runtime (plugins, templating, multi-tenant JS execution, or any `eval`/`Function` sink), they may be able to override built-ins and bypass those checks.

Defensive posture:

- Don’t rely on a single check like `hasOwnProperty` or `str.includes('__proto__')` for security
- Validate structure with schemas/allowlists (preferred) instead of substring blacklists
- Add regression tests for `__proto__` and `constructor.prototype` payloads
- Run SAST + unit tests that include pollution probes

## Detection / verification probes

Add a CI test that fails if a pollution primitive is possible:

```js
function assertNotPolluted() {
  if (({}).polluted !== undefined) throw new Error('Prototype polluted');
  if (({}).isAdmin !== undefined) throw new Error('Prototype polluted');
}

assertNotPolluted();
// exercise your parser/merge/setter on attacker-controlled inputs
assertNotPolluted();
```

Example payload families to test:

- `{"__proto__":{"polluted":"yes"}}`
- path-based setters: `"__proto__.polluted"`, `"constructor.prototype.polluted"`

## Incident response notes

If you suspect prototype pollution in production:

- Identify the entry point (JSON body, query parser, webhooks, config import, etc.)
- Search logs for keys containing `__proto__`, `constructor`, `prototype`
- Assume secondary impact until proven otherwise (authz decisions, template rendering, command execution, SSRF settings)

## References

- GitHub Advisory (example): `deephas` prototype pollution via `constructor.prototype` / `__proto__` (CVE-2026-25047)
- GitHub Advisory (example): `makerjs.extendObject` unsafe property copying can enable prototype pollution-style attacks (CVE-2026-24888)
