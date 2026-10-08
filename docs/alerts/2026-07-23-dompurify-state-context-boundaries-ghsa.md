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

## October 1 follow-up: IN_PLACE hook-detached subtrees keep armed handlers

[GHSA-p98j-92pf-mc4p](https://github.com/advisories/GHSA-p98j-92pf-mc4p) (DOMPurify `>=3.4.13 <=3.4.15`, fixed **3.4.16**) extends the state/context axis to hook-interaction coverage drift. In `IN_PLACE` mode the library neutralizes any subtree a hook detaches (strip non-allow-listed attributes) so queued resource events cannot fire in page scope after `sanitize()` returns — but that `_handleHookDetachedNode` guard is wired only into the `beforeSanitizeElements` and `uponSanitizeElement` hook sites. A documented, supported pattern — an `afterSanitizeElements`/`afterSanitizeAttributes` hook that removes a node — detaches the subtree with **no** neutralization, and the post-walk `IN_PLACE` cleanup pass iterates only `DOMPurify.removed`, which by design excludes hook-detached nodes. Result: descendant `on*` handlers (e.g. an `<img onerror>` that started loading when the caller built the tree) remain armed on the caller's live tree after sanitize returns.

Audit rule for any in-place sanitizer with user- or app-registered hooks: **enumerate every lifecycle point where a node can leave the tree and check the cleanup path covers each one.** The fix history proves the pattern (GHSA-55q2-fjhq-7xh7 added the guard at two sites, missed the rest). Validation harness:

1. In a disposable owned page, register an afterSanitize hook that removes a marker element, and a beforeSanitize hook that removes an identical one.
2. Give both subtrees a resource-event canary (`<img src=x onerror="console.log('skillz-detach-marker')">`) that begins loading pre-sanitize.
3. Compare: before-site detach should neutralize (no marker fires); after-site detach on an affected version fires the handler post-return.
4. Negative control on 3.4.16 with the same hook set.

Report shape: sanitizer version, mode (`IN_PLACE` vs string), hook registration order and site, whether the detached node appears in `DOMPurify.removed`, and whether the marker fires after `sanitize()` returns. This is a hook-interaction defect class, not an allow-list bypass — keep that distinction in the report; the app's hooks need not be misconfigured for it to trigger.

## Related Skillz Wiki guidance

- The earlier [`selectedcontent` browser re-cloning check](2026-06-01-rattler-vitest-dompurify-mcp-boundary-batch-ghsa.md#dompurify-selectedcontent-xss-check) covers a separate post-sanitization DOM mutation pattern.
- [AngleSharp HTML integration-point checks](2026-07-17-skipper-cloudtak-anglesharp-boundaries-ghsa.md) provide a parallel parser-context methodology for non-browser sanitizers.

## October 6 follow-up: IN_PLACE force-removal misses the rawtext text-content carrier (GHSA-6688-9rhm-gjv2, ≤3.4.15, fixed 3.4.16)

The 3.4.9 IN_PLACE hardening added a fail-closed `TypeError` when a force-removed node can't detach, plus a `_neutralizeSubtree` pass stripping non-allowlisted **attributes** from removed subtrees. Both miss the case where the force-removed root **is a rawtext element** (`<style>`): the payload lives in the node's *text*, the node detaches cleanly (guard never fires), neutralization strips nothing (no attributes), and the `IN_PLACE` return hands the caller the detached node whose text still carries attacker markup — a later pure-HTML reparse of that tree executes it.

- Durable rule for any sanitizer with an in-place/detach-and-return contract: **the neutralization pass must cover every carrier form, not just the attribute form** — attributes, text content of rawtext elements (`style`, `script`, `textarea`, `title`), and comment nodes each need explicit coverage. When auditing, enumerate carrier forms as a battery: same payload placed in attribute vs rawtext-text vs comment, diff what survives removal.
- Validation harness (owned disposable page): `DOMPurify.sanitize(node, {IN_PLACE:true})` on a tree whose root is `<style>` containing markup that arms a benign marker on reparse; check whether the returned node's text still contains the payload and whether the marker fires after a caller-side re-insert. Negative control on 3.4.16. This continues the page's thesis: DOMPurify's fix surface is state/lifecycle interaction, not the allow-list.

## October 8 20:1xZ follow-up: `enshrined/svg-sanitize` — the sanitizer's XML parser and the browser's HTML5 parser disagree about the same bytes (CVE-2026-107380 / [GHSA-9rjx-3jch-6vjf](https://github.com/advisories/GHSA-9rjx-3jch-6vjf) XSS, CVE-2026-107381 / [GHSA-m9xh-6747-9r6f](https://github.com/advisories/GHSA-m9xh-6747-9r6f) ordering, CVE-2026-107379 / [GHSA-v383-3rw5-q8rf](https://github.com/advisories/GHSA-v383-3rw5-q8rf) DTD crash)

The PHP SVG sanitizer with ~45M Packagist downloads — embedded in the WordPress **Safe SVG** plugin (1M+ active installs), TYPO3, Drupal, and 90+ dependents — shipped a stored-XSS bypass that is this page's core thesis wearing a different language: **the sanitizer decides with an XML parser, the browser renders with an HTML5 parser, and the two resolve the same token differently.**

1. **DTD entity / HTML5 Named Character Reference collision** ([GHSA-9rjx-3jch-6vjf](https://github.com/advisories/GHSA-9rjx-3jch-6vjf), fixed 45.2). Define an XML entity whose *name* collides with an HTML5 NCR: `<!ENTITY Tab "#">`. In the sanitizer's XML context `&Tab;` expands to `#`, so `href="&Tab;javascript:…"` looks like a fragment identifier and `isHrefSafeValue()` passes it. But `saveXML()` re-emits the **entity reference**, not the expanded value, and the DOCTYPE that defines it is stripped from the output. In the browser, with no DOCTYPE, `&Tab;` resolves as the HTML5 NCR = U+0009 TAB; the URL parser strips leading whitespace; `javascript:` executes. No PHP-version or ext/dom bug required — pure parser-semantic mismatch, inline-SVG render path only.
2. **Build-graph-before-normalize casing ordering** ([GHSA-m9xh-6747-9r6f](https://github.com/advisories/GHSA-m9xh-6747-9r6f)). `Resolver::processReferences()` selects `<use>` nodes with the **case-sensitive** XPath predicate `use[@href or @xlink:href]`; writing the attribute as `xlink:HrEf` keeps it out of the nesting-DoS reference graph, and `Sanitizer::cleanHrefAttributes()` then *rewrites* the mixed-case attribute back to canonical `xlink:href` later in the same pass — the sanitizer hands back a fully live `<use>` nesting bomb it would have stripped at canonical casing. Mirror image of CVE-2025-55166: that fix made href *value* checking case-insensitive while node *selection* stayed case-sensitive.
3. **DTD attribute-declaration crash** ([GHSA-v383-3rw5-q8rf](https://github.com/advisories/GHSA-v383-3rw5-q8rf)) — parser-availability leg, tracked as fuzzing input for the same pipeline.

Durable rules for any sanitize-then-inline-render pipeline (PHP or otherwise):

- **Entity-semantics battery.** For every allow-verdict the sanitizer makes on an attribute value, test whether the sanitizer and the consuming renderer resolve the same bytes differently: entity-name collisions with HTML5 NCRs (`&Tab;` `&NewLine;` `&colon;` defined in a DTD to expand to something *other* than their HTML5 meaning), character references the XML parser rejects but HTML5 resolves, and references preserved-then-redefined. Evidence shape: sanitizer-version + saved-output diff showing the entity reference surviving output + one inert marker firing on inline render.
- **Case-variant replay of the fix-history corpus.** Every historical case-variant bypass for a sanitizer is a candidate again wherever node *selection* is case-sensitive while attribute *normalization* runs in a later pass. Before concluding a case-insensitivity fix is complete, check whether the fix touched value checking, node selection, *and* pass ordering — the grep is the pipeline's pass order: `sanitize()` build-graph → normalize-attrs, and ask whether any decision was made against names/values the next pass rewrites. Same post-sanitizer-transformation invariant as this page's reparse legs and the Sept 22 sanitize-then-rewrite page.
- **Target-facing sweep.** Inline-SVG upload surfaces on WordPress (Safe SVG present = theme renders SVG inline), TYPO3, and Drupal are the standing high-prevalence target for battery one. Prove with an inert `alert(document.domain)`-class marker on your own install; do not test on client sites without explicit authorization.

Tracked from the same 19:41Z batch without publication: **CairoSVG** ≤2.9 quadratic-time DoS in the `<path d>` tokenizer (re-scan of the remaining string per step) and `draw_markers` (`list.pop(0)` drain) — sub-MiB SVG ≈ 18 s CPU on `svg2png`/`svg2pdf`; operator note only: on any SVG-rendering target (thumbnails, avatars, PDF export), measure 50k/100k/200k segment scaling (≈4× per doubling = quadratic) before concluding the render farm has an availability story. **music-metadata** five-pack (APEv2/ID3v2/EBML length-before-allocation exhaustion, `.dsf` uncatchable crash residual, MP4 `stsd` zero-size infinite loop) and **amqp091-go** pre-negotiation frame limit — parser-DoS class per precedent.
