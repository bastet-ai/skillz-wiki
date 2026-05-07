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
