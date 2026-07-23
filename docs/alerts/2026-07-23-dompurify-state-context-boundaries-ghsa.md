# DOMPurify state, policy, and reparse boundary checks

Source: hourly offensive-security scan, 2026-07-23 GitHub advisory update. Primary entries: [GHSA-h8r8-wccr-v5f2](https://github.com/advisories/GHSA-h8r8-wccr-v5f2) / CVE-2026-65914, [GHSA-cj63-jhhr-wcxv](https://github.com/advisories/GHSA-cj63-jhhr-wcxv) / CVE-2026-65913, [GHSA-cjmm-f4jc-qw8r](https://github.com/advisories/GHSA-cjmm-f4jc-qw8r) / CVE-2026-65912, [GHSA-39q2-94rc-95cp](https://github.com/advisories/GHSA-39q2-94rc-95cp) / CVE-2026-65903, [GHSA-76mc-f452-cxcm](https://github.com/advisories/GHSA-76mc-f452-cxcm) / CVE-2026-65902, [GHSA-x4vx-rjvf-j5p4](https://github.com/advisories/GHSA-x4vx-rjvf-j5p4) / CVE-2026-65901, [GHSA-gvmj-g25r-r7wr](https://github.com/advisories/GHSA-gvmj-g25r-r7wr) / CVE-2026-65900, [GHSA-vxr8-fq34-vvx9](https://github.com/advisories/GHSA-vxr8-fq34-vvx9) / CVE-2026-65899, and [GHSA-cmwh-pvxp-8882](https://github.com/advisories/GHSA-cmwh-pvxp-8882) / CVE-2026-65898.

This wave is durable for bug hunters because it separates three boundaries that a simple "input passed through DOMPurify" claim hides:

1. the policy assembled from profiles, callback allowlists, forbids, and hooks;
2. mutable sanitizer-instance state that can survive one call and influence another; and
3. browser or framework processing that reparses, adopts, normalizes, or evaluates sanitized output in a different context.

!!! warning "Authorized validation only"
    Use a disposable browser profile, local fixture application, same-process sanitizer harness, synthetic markup, and harmless DOM markers. Do not test stored payloads against real users, collect cookies or tokens, use production rich-text content, or infer XSS from package version alone. Prove the target's exact sanitizer configuration and downstream sink.

## Boundary map

| Advisory | Triggering boundary | Useful positive signal | Important negative control |
| --- | --- | --- | --- |
| [GHSA-h8r8-wccr-v5f2](https://github.com/advisories/GHSA-h8r8-wccr-v5f2) | sanitized markup is concatenated into a special wrapper and reparsed | an inert event marker appears only after the second parse inside `script`, `xmp`, `iframe`, `noembed`, `noframes`, or `noscript` context | direct insertion without the wrapper does not produce the marker |
| [GHSA-cj63-jhhr-wcxv](https://github.com/advisories/GHSA-cj63-jhhr-wcxv) | `USE_PROFILES` rebuilds an attribute allowlist as an array while polluted `Array.prototype` properties are still consulted | a synthetic event attribute survives only after the specific prototype property exists | a fresh realm or unpolluted prototype strips it |
| [GHSA-cjmm-f4jc-qw8r](https://github.com/advisories/GHSA-cjmm-f4jc-qw8r) | functional `ADD_ATTR` approval short-circuits URI validation | a canary unsafe-scheme value survives for the approved attribute/tag pair | the same value is stripped with an array allowlist or rejecting predicate |
| [GHSA-39q2-94rc-95cp](https://github.com/advisories/GHSA-39q2-94rc-95cp) | functional `ADD_TAGS` approval wins before `FORBID_TAGS` is evaluated | a tag present in both decisions survives | array-form `ADD_TAGS` or a patched build gives `FORBID_TAGS` precedence |
| [GHSA-76mc-f452-cxcm](https://github.com/advisories/GHSA-76mc-f452-cxcm) | a hook mutates `data.allowedTags` or `data.allowedAttributes`, which aliases a shared default set | the widened policy persists after hooks and config are removed | a fresh DOMPurify instance strips the marker again |
| [GHSA-cmwh-pvxp-8882](https://github.com/advisories/GHSA-cmwh-pvxp-8882) | `setConfig()` causes later calls to skip the clone guard before an attribute hook mutates the live set | one trusted render makes the same attribute survive on a later untrusted element | equivalent per-call config on the fixed path does not leak state |
| [GHSA-vxr8-fq34-vvx9](https://github.com/advisories/GHSA-vxr8-fq34-vvx9) | a reused instance retains a custom Trusted Types policy after `clearConfig()` | later `RETURN_TRUSTED_TYPE` output is created by the earlier canary policy | ordinary string output and a fresh instance remain independently sanitized |
| [GHSA-gvmj-g25r-r7wr](https://github.com/advisories/GHSA-gvmj-g25r-r7wr) | DOM-return modes do not normalize and rescan split template expressions inside `template.content` | two harmless fragments become a complete marker expression after downstream normalization | string output and non-template content do not preserve the split expression |
| [GHSA-x4vx-rjvf-j5p4](https://github.com/advisories/GHSA-x4vx-rjvf-j5p4) | `IN_PLACE` accepts a hostile live DOM object from a lower-trust same-origin realm | the real node type and its observable `nodeName` disagree, and a forbidden node remains after sanitization | string input, `cloneNode()`, or `importNode()` loses the hostile object semantics |

These checks are configuration- and sink-dependent. A dependency scanner result is reconnaissance, not proof.

## Recon: find the real sanitizer-to-sink path

Search application bundles and source maps, browser extensions, CMS preview code, rich-text editors, email/template previews, and plugin APIs for both sanitizer setup and later transformations:

```text
DOMPurify.sanitize
DOMPurify.setConfig
DOMPurify.addHook
USE_PROFILES
ADD_ATTR
ADD_TAGS
FORBID_TAGS
RETURN_DOM
RETURN_DOM_FRAGMENT
IN_PLACE
RETURN_TRUSTED_TYPE
SAFE_FOR_TEMPLATES
innerHTML
insertAdjacentHTML
createContextualFragment
adoptNode
normalize
```

For each reachable flow, capture:

- the DOMPurify version and whether the browser bundle differs from the lockfile;
- whether one instance is reused across widgets, tenants, plugins, requests, or trust levels;
- global `setConfig()` calls and all hooks, including code loaded after application bootstrap;
- whether configuration fields are arrays or predicate functions;
- the input representation: string, local DOM node, or live node supplied by another realm;
- the output representation: string, `DocumentFragment`, live DOM, or `TrustedHTML`;
- every operation after sanitization, especially string concatenation, wrapper insertion, reparsing, template normalization, adoption, and framework compilation; and
- the browser engine and exact sink that turns retained markup or policy state into an observable marker.

Do not stop at a call to `sanitize()`. The strongest reports reconstruct **attacker-controlled source -> effective policy -> sanitizer output -> downstream transformation -> executable sink**.

## Replayable validation workflows

### 1. Context-switch and second-parse matrix

Use this when sanitized strings are wrapped, templated, or reinserted through another HTML parser.

1. Mirror the target's exact sanitize call in a local fixture.
2. Use a benign marker attribute split by a wrapper-closing sequence; the marker should only set a local variable or add a test-only DOM attribute.
3. Record the immediate sanitized string before any application processing.
4. Insert it through each target-reachable path:
   - direct `innerHTML` into an ordinary container;
   - concatenation inside each special wrapper the target uses;
   - `Range.createContextualFragment()` or template parsing, if present; and
   - the actual framework or editor render path.
5. Capture the DOM after the second parse and whether the inert marker fires.
6. Repeat on DOMPurify `3.3.2+` for the re-contextualization advisory and keep direct insertion as a negative control.

Report the parser transition, not merely the payload: **sanitized tree/string in context A -> target concatenation or wrapper -> browser parse in context B -> newly active node/attribute**.

### 2. Effective policy precedence matrix

Exercise only the configuration forms the target actually uses.

| Test | Setup | Question |
| --- | --- | --- |
| Profile/prototype | `USE_PROFILES` plus one synthetic `Array.prototype` canary property | Does inherited state act like an own allowlist entry? |
| Functional attribute add | predicate approves one URI-bearing attribute on one tag | Does approval bypass scheme validation? |
| Functional tag add | the same test tag is returned by `ADD_TAGS` and listed in `FORBID_TAGS` | Which decision wins? |
| Patched control | identical fixture on the first fixed release | Does the intended validation or forbid decision now run? |

Use harmless values and inspect serialized output; activation is unnecessary until retention is proven. For URI tests, use a local marker scheme handled only by the fixture rather than a navigation or network callback.

Confirmed version boundaries from the advisories are:

- `USE_PROFILES` prototype and functional `ADD_ATTR`: fixed in `3.3.2`;
- functional `ADD_TAGS` versus `FORBID_TAGS`: fixed in `3.4.0`; and
- later state issues have separate boundaries below, so passing one fixed-version control does not clear the others.

### 3. Shared-instance contamination sequence

This workflow distinguishes a real cross-call policy leak from a deliberately permissive single call.

1. Create one DOMPurify instance in a fresh local browser realm or `jsdom` process.
2. Run an untrusted baseline and save the sanitized output.
3. Register the target-equivalent hook or canary Trusted Types policy.
4. Run one explicitly trusted canary render.
5. Remove hooks or call the cleanup API the application relies on.
6. Run the original untrusted input again on the same instance.
7. Run the same input on a newly created instance.
8. Compare outputs as an ordered trace rather than as isolated screenshots.

For hook mutation, test both ordinary per-call configuration and the target's `setConfig()` path. For Trusted Types, compare string output with `RETURN_TRUSTED_TYPE` output after `clearConfig()`; the advisory's boundary is retained policy state, not a generic string-sanitization bypass.

Relevant fixed releases are:

- hook mutation of shared defaults: `3.4.7`;
- retained Trusted Types policy after `clearConfig()`: `3.4.9`; and
- `setConfig()` bypass of the attribute clone guard: `3.4.11`.

A valid report should show **baseline blocked -> trusted/configuring call -> cleanup -> later untrusted call allowed on the same instance -> fresh instance blocked**.

### 4. DOM-return and live-object checks

Use DOM output tests only when the target requests `RETURN_DOM`, `RETURN_DOM_FRAGMENT`, or `IN_PLACE`.

For `SAFE_FOR_TEMPLATES`:

1. Place a harmless template marker across two text fragments under `template.content`.
2. Sanitize with the target's DOM-return mode and `SAFE_FOR_TEMPLATES: true`.
3. Inspect child nodes before normalization.
4. Invoke only the target's normal downstream normalization or template-read step.
5. Confirm whether the fragments merge into the marker expression; do not execute arbitrary expressions.
6. Compare string output and DOMPurify `3.4.8+`.

For hostile live nodes:

1. Use an owned same-origin iframe or popup in a disposable page.
2. Construct a live canary node whose true element type and own observable `nodeName` differ.
3. Pass the node by reference to the target-equivalent `IN_PLACE` call.
4. Inspect whether a forbidden canary node remains; a DOM attribute or array append is enough if activation must be checked.
5. Compare direct reference/adoption against `cloneNode()`, `importNode()`, and string serialization.

The live-object issue does not establish risk for ordinary string input. It requires a lower-trust same-origin realm or plugin to supply a live object across the application's trust boundary. The advisory listed affected `3.4.6` with no first patched version in the GitHub record at scan time; report that uncertainty rather than inventing a fixed threshold.

## Evidence and reporting

Prefer a compact decision table:

| Instance | Prior trusted/config call | Cleanup | Input form | Output mode | Downstream operation | Marker retained/fired |
| --- | --- | --- | --- | --- | --- | --- |
| fresh | none | n/a | string | string | direct insertion | no |
| shared | hook or policy canary | target cleanup | string | string or TrustedHTML | target sink | yes/no |
| shared | same | same | DOM node | `IN_PLACE` | adopt/append | yes/no |
| fresh patched | same sequence | same | same | same | same | no |

Lead with the reachable preconditions. Distinguish:

- retained unsafe markup from actual execution;
- first-parse sanitizer behavior from second-parse browser behavior;
- explicit one-call permissiveness from cross-call state contamination;
- string-input behavior from hostile live-object behavior; and
- DOMPurify defects from application-defined callback policies that are simply too broad.

Capture package and bundle versions, browser engine, effective config, hook registration order, instance lifetime, raw sanitizer output, post-transform DOM, inert marker result, and a patched or fresh-instance negative control. Redact real content and user identifiers.

## Related Skillz Wiki guidance

- The earlier [`selectedcontent` browser re-cloning check](2026-06-01-rattler-vitest-dompurify-mcp-boundary-batch-ghsa.md#dompurify-selectedcontent-xss-check) covers a separate post-sanitization DOM mutation pattern.
- [AngleSharp HTML integration-point checks](2026-07-17-skipper-cloudtak-anglesharp-boundaries-ghsa.md) provide a parallel parser-context methodology for non-browser sanitizers.
