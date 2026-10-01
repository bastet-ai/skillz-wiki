# Svelte devalue own-`__proto__` deserialization boundary

**Signal:** The **2026-05-14 22:15 UTC** advisory scan surfaced [GHSA-mwv9-gp5h-frr4](https://github.com/advisories/GHSA-mwv9-gp5h-frr4): Svelte's `devalue` package could emit objects with own `__proto__` properties from `devalue.parse()` and `devalue.unflatten()`.

## Advisory

- **Package:** npm `devalue`
- **Affected:** `>= 4.0.0, < 5.6.4`
- **Fixed:** `5.6.4`
- **Severity:** low in isolation, but durable as a deserialization-boundary lesson
- **Issue:** parsed/unflattened attacker-controlled serialized data could produce objects carrying an own `__proto__` key. That may not immediately pollute prototypes, but it becomes dangerous when the resulting object later crosses into merge, clone, assignment, templating, policy, or framework state sinks that treat `__proto__` specially.

## Why this matters

Deserializer fixes are often assessed only at the parser. The safer question is what happens next: serialized data commonly moves into caches, hydration state, route data, form defaults, configuration objects, or deep-merge helpers. An own `__proto__` property is a boundary marker that downstream code must not accidentally convert into prototype mutation or inherited-policy reads.

## Triage

1. Upgrade `devalue` to `5.6.4+` anywhere server-rendered, hydrated, cached, or user-influenced data is parsed with `devalue.parse()` or `devalue.unflatten()`.
2. Search code for parsed devalue output flowing into `Object.assign`, spread/clone helpers, recursive merge utilities, stores, route data, request/session state, or template context construction.
3. Add regression payloads containing own `__proto__`, `constructor`, and `prototype` keys and assert prototypes remain unchanged after all downstream transforms.
4. If untrusted serialized data was accepted, review logs and cache entries for prototype-reserved keys before reusing old hydrated state.

## Durable controls

- Treat deserializer output as hostile until it is projected through a schema into null-prototype dictionaries, `Map`, or typed application objects.
- Block prototype-reserved keys at every nested assignment boundary, not just in the first parser.
- Prefer explicit allowlists for hydration/config/state fields; do not pass raw parsed objects into broad merge utilities.
- Test source-and-sink chains: a low-severity parser primitive can become high impact when paired with a downstream prototype-pollution sink or inherited-property security decision.

## October 1 follow-up: null-prototype key coercion reopens the `__proto__` rejection (GHSA-4q55-j62x-fr9h)

[GHSA-4q55-j62x-fr9h](https://github.com/advisories/GHSA-4q55-j62x-fr9h) (medium, devalue) is a direct regression of this page's own class: malformed **null-prototype object keys** bypass the `__proto__` own-property rejection via property-key coercion, letting `parse` create objects with a `__proto__` own property again. Maintainers rate standalone impact low (this matches `JSON.parse` semantics), but the durable rule is this page's rule restated: **key-rejection filters are written against the parser's happy-path key representation** — feed the filter every key-representation variant (null-prototype inputs, coercion-prone shapes, exotic strings), and re-run the *previous* advisory's key battery on each "fixed" build, since the fix gates the spelling it was written for.
