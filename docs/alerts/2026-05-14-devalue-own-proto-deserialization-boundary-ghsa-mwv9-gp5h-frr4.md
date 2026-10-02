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

## October 2 follow-up: the serialization side leaks shared memory ([GHSA-j22f-vq7h-c4qm](https://github.com/advisories/GHSA-j22f-vq7h-c4qm) / CVE-2026-92708, high)

Source: GHSA published 2026-10-01 15:18Z, devalue `>= 5.1.0, <= 5.9.2`, fixed `5.9.3`. `stringify`/`uneval` serialize a typed array by emitting its **backing `ArrayBuffer`**, not just the view. For a Node `Buffer` the backing store is Node's **process-wide shared buffer pool**, so serializing even a 2-byte `Buffer` copies up to ~64 KB of unrelated process memory — bytes from other in-flight requests — into the output. In an SSR framework (SvelteKit, Nuxt) a public page whose `load()` returns a small `Buffer` (or a small `readFileSync` result) ships **another user's request body or `Authorization` header** in its own HTML. Unauthenticated, silent, and the advisory measured ~43,000× amplification.

The structural lesson extends this page's source→sink framing to the *other* direction:

1. **This page tracks the parse side; the serialize side has none of those guards.** The `parse`/`unflatten` prototype-pollution and DoS guards added across this page's advisory history never applied here — this fires on every SSR render, not only when parsing untrusted input. When auditing a serializer, enumerate both halves (serialize and parse) and check which invariants were only ever applied to one.
2. **The view/buffer distinction is an information-disclosure primitive.** Any serializer that walks `.buffer` (or `.buffer`-adjacent fields like `byteOffset`-less copies) instead of the view's `[byteOffset, byteOffset+byteLength)` window leaks pool neighbors. The fix idiom — `new Uint8Array(buffer)` copies the view — is also the detection fingerprint: grep SSR `load()`/data-return paths for raw `Buffer` values crossing into serialized state.
3. **Hunt shape for operators:** on SvelteKit/Nuxt targets, look for public routes whose `load()` touches the filesystem or returns binary (icons, PDFs, image thumbs, `Buffer.from(...)` results). Request the page twice under two separate connections with a unique marker header/body in request A, then scan request B's rendered HTML for the marker — a cross-request byte bleed is the proof. Evidence stays at your own markers between your own clients; never attempt to recover other users' traffic.
4. **Version fingerprint:** `5.1.0`–`5.9.2` is a wide affected band and the bug is silent, so lockfile presence of devalue in that range plus any `Buffer` in serialized state is the reportable condition, independent of an error or observable crash.
