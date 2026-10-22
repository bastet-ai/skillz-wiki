# DOMPurify mXSS and Ivanti EPMM KEV boundary guidance

**Signal:** The 2026-05-07 hourly scan found two durable defensive items: GitHub Security Advisories REST fallback published **DOMPurify mutation-XSS via re-contextualization** ([GHSA-h8r8-wccr-v5f2](https://github.com/advisories/GHSA-h8r8-wccr-v5f2)), and CISA KEV added actively exploited **Ivanti Endpoint Manager Mobile (EPMM) improper input validation RCE** ([CVE-2026-6973](https://www.cve.org/CVERecord?id=CVE-2026-6973)) with a **2026-05-10** due date.

## Advisories covered

- **DOMPurify mutation-XSS via re-contextualization** — [GHSA-h8r8-wccr-v5f2](https://github.com/advisories/GHSA-h8r8-wccr-v5f2): sanitized HTML can become executable when an application takes DOMPurify output, wraps it in special parsing contexts such as `script`, `xmp`, `iframe`, `noembed`, `noframes`, or `noscript`, and reparses it with `innerHTML`. The advisory describes attacker-controlled closing sequences mutating into event-handler markup during the second parse.
- **Ivanti EPMM improper input validation RCE in KEV** — [CVE-2026-6973](https://www.cve.org/CVERecord?id=CVE-2026-6973): CISA says remotely authenticated administrative users can achieve remote code execution in Ivanti Endpoint Manager Mobile. Federal due date is **2026-05-10**; all exposed or internet-reachable EPMM deployments should treat this as urgent because KEV means exploitation is already observed.

## Why this is durable

Both items are boundary failures after an apparent safety check. DOMPurify may correctly sanitize the first parse tree, but the application changes the browser parsing context afterward. Ivanti EPMM administrative interfaces sit at a device-management control plane where an input-validation bug becomes remote code execution with fleet-level impact. The reusable lesson: validation must be tied to the final sink and privilege boundary, not to an earlier intermediate representation.

## Immediate triage

1. **For DOMPurify users:** find code that sanitizes HTML and later concatenates or wraps it before assigning to `innerHTML`, `outerHTML`, template HTML, rich-text previews, iframe bodies, or server-rendered hydration islands.
2. Block or refactor patterns that place sanitized user-controlled content inside `script`, `xmp`, `iframe`, `noembed`, `noframes`, `noscript`, SVG/MathML, or other context-changing wrappers. Prefer DOM node construction and text nodes for wrapper content.
3. Add regression tests for payloads containing closing wrapper sequences inside attributes, then render through the exact production sink rather than only testing the sanitizer return value.
4. **For Ivanti EPMM:** identify every EPMM instance, especially internet-facing admin or management portals. Apply Ivanti mitigations/patches, or isolate/discontinue the product if mitigations are unavailable.
5. Because the KEV entry allows authenticated admin RCE, review admin account history, recent configuration changes, uploaded packages/profiles, command execution artifacts, and outbound connections from EPMM hosts before and after remediation.

## Hunt prompts

- `DOMPurify.sanitize(...)` followed by string concatenation, template interpolation, wrapper tags, or a later `.innerHTML =` assignment.
- Sanitized rich-text values stored in databases and re-rendered later into a different component, editor preview, email template, or embed wrapper.
- Client-side alerts, CSP violations, unexpected event-handler attributes, or reports that only trigger after content is saved and viewed in another page.
- Ivanti EPMM admin logins from unusual IPs, new administrative users, unexpected device-management policies, package/profile uploads, task execution, or shell/process activity on the management server.
- EPMM egress to unfamiliar infrastructure, webshell-like files, modified scheduled jobs/services, or log gaps around the exploitation window.

## Durable controls

- Treat sanitizer output as safe only for the sink and parsing context it was validated for. If the context changes, re-encode or rebuild through safe DOM APIs.
- Keep dangerous wrapper contexts out of user-content rendering paths; if a wrapper is unavoidable, insert untrusted content as text, not HTML.
- Pair HTML sanitization with strict CSP, Trusted Types where supported, and sink-level tests that cover browser mutation behavior.
- Place device-management control planes behind VPN/zero-trust access, phishing-resistant MFA, admin allowlists, and strong logging; do not expose EPMM admin surfaces directly to the internet.
- For KEV-class management-plane RCE, patching is not the finish line: preserve evidence, rotate credentials/tokens reachable from the server, verify integrity, and rebuild from known-good images if compromise indicators appear.

## October 22 follow-up: ammonia — the sanitizer strips an attribute, and the attribute was holding the child in a parsing context (CVE-2026-63430 / [GHSA-9jh8-v38h-cvhr](https://github.com/advisories/GHSA-9jh8-v38h-cvhr), ammonia < 3.3.2 / 4.x < 4.0.2 / 4.1.x < 4.1.3, [writeup](https://ivan09999.github.io/ammonia-mxss))

The Rust-side member of this page's mXSS family, and the cleanest statement of the mechanism yet. ammonia's `annotation-xml` handling: the namespace filter runs on the *input* DOM, where `<math><annotation-xml encoding="text/html"><gadget></annotation-xml></math>` parses children as HTML and passes tag allowlists; the attribute filter then strips `encoding` because it isn't allowlisted. Post-sanitize, the browser re-parses the output with `annotation-xml` as a plain MathML element — children re-enter MathML parsing, and a gadget crafted to mean different things in HTML vs MathML context executes.

**The generalization: a sanitizer's attribute allowlist must be checked against the HTML parsing algorithm, not just against XSS.** Some attributes are *parsing-context carriers* — `encoding` on `annotation-xml`, `srcdoc` on iframe, `type` on `<script>`/`<template>`, `sandbox` — and stripping them silently changes how everything downstream re-parses. Validation happened on one context; the browser honors another. This is the same defect shape as the SmarterMail iCal MathML foreign-content leg ([Oct 9 page](2026-10-09-smartermail-wave-jwt-stale-role-refresh-mount-script-containment-bypass-and-mathml-mxss-ghsa.md)) and the ApostropheCMS `isImplied-close` discard escape ([Oct 20 page](2026-10-20-apostrophecms-coordinated-wave-permission-false-rest-read-projection-proto-delete-noscript-discard-and-url-session-token-ghsa.md)): the sanitizer's internal DOM model and the browser's tokenizer disagree *after* sanitizer mutation.

Operator battery for any product with a Rust (ammonia), JS (DOMPurify/sanitize-html/custom), or Go (bluemonday) sanitizer in front of user HTML:

1. **Enumerate the enabled tag set from public render output**, then test the integration-point matrix: `math`, `svg`, `foreignObject`, `annotation-xml`, `desc`, `title` × `encoding="text/html"` and `text/html+template` variants, each present / garbled / **absent**. The absent leg is the sanitizer's own mutation — compare browser-parsed DOM before and after sanitize for the same input; a diff in child-element namespaces is the finding.
2. **Raw-text-element dependency check.** The ammonia gadget required one raw-text HTML element to survive the allowlist (`title`, `textarea`, `xmp`, `iframe`, `noembed`, `noframes`, `plaintext`, `noscript`, `style`, `script`). If a product enables any of these *and* MathML/SVG, it is in the vulnerable configuration; if it enables neither, the class is closed there — fingerprint the config from outside before spending time on the class.
3. **Attribute-strip differential**: for every allowlisted structural tag, sanitize a version of the payload with each non-allowlisted attribute attached and check whether stripping that attribute changes child parsing (context-carrying attribute grep against the HTML spec's conditionally-including-integration-points table).
4. Fingerprint: ammonia fix commits `004bf2c`/`7ac3fd3`/`b51bf4f` ship 3.3.2/4.0.2/4.1.3; Rust services exposing user-rendered HTML (many use ammonia precisely because it "is DOM-based") are the target set, and the advisory's own impact note (requires MathML + a raw-text tag) means most deployments are not affected — prove the config first.
