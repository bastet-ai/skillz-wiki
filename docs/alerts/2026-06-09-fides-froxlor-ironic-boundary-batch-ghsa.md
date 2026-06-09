# Fides banner override, Froxlor API 2FA, and Ironic image-boundary checks

Source: hourly offensive-security scan, 2026-06-09. Primary entries: GitHub advisories [GHSA-5qrq-9645-g5g2](https://github.com/advisories/GHSA-5qrq-9645-g5g2), [GHSA-f9rx-7wf7-jr36](https://github.com/advisories/GHSA-f9rx-7wf7-jr36), and [GHSA-rmxr-45gj-889w](https://github.com/advisories/GHSA-rmxr-45gj-889w).

This batch is durable because it captures three reusable operator patterns: client-side consent-banner override values reaching trusted HTML sinks, API credentials bypassing a UI-only 2FA boundary, and bare-metal provisioning agents executing functionality from an untrusted tenant-supplied image.

## What changed

- **Fides consent-banner DOM XSS** — Fides Enterprise deployments that load `fides.js` and enable HTML-formatted banner descriptions can render `fides_description` override values from a URL parameter, JavaScript global, or cookie as live HTML. The advisory notes that defaults are not affected unless HTML descriptions are enabled, but affected sites can be triggered by a crafted visitor URL and the cookie source can make the payload persist on the embedding origin.
- **Froxlor API bypasses 2FA** — vulnerable `froxlor/froxlor < 2.3.7` enforces TOTP during web UI login, but `FroxlorRPC::validateAuth` accepts API key/secret authentication without checking the account's 2FA state. If an API key and secret are exposed for a 2FA-protected admin or customer account, the API becomes a second-factor bypass path.
- **OpenStack Ironic Python Agent untrusted image execution** — `ironic-python-agent >= 1.0.0, <= 11.5.0` can execute `grub-install` from inside a deployed partition image chroot. In bare-metal provisioning workflows, a malicious tenant-controlled image can therefore influence code execution inside the provisioning boundary.

## Operator triage

1. **Find exercised feature paths, not package names alone.** Fides impact requires `fides.js` on an embedding site plus HTML descriptions enabled; Froxlor impact requires API enabled and reachable API credentials; Ironic impact requires IPA deployment against tenant- or tester-supplied partition images.
2. **Map the principal boundary:** visitor-controlled URL/cookie to consent-banner DOM, leaked API key to 2FA-protected account operations, or tenant image content to provisioning-agent execution context.
3. **Prioritize high-value contexts:** production marketing sites with privacy banners on authenticated domains, hosting panels where API keys are stored in CI or customer automation, and OpenStack bare-metal environments that allow custom images during tenant provisioning.
4. **Use canaries instead of secrets.** Strong reports demonstrate the crossed boundary with an inert DOM marker, a disposable Froxlor API key, or a lab image marker rather than reading real credentials, customer files, or host data.
5. **Separate configuration from exploitability.** A Fides deployment without HTML descriptions, a Froxlor account without API credentials, or an Ironic environment that does not accept untrusted images may have package exposure without a practical exploit path.

## Replayable validation boundaries

### Fides banner override checks

- Only test sites where client-side testing is authorized. Use a harmless marker such as `alert(document.domain)` only in lab or approved bug-bounty scope; prefer a non-executing DOM marker when possible.
- Confirm that the site loads `fides.js`, identify the active locale, and verify whether HTML-formatted banner descriptions are enabled. The advisory notes that the override language must match the active locale for the parameter path.
- Test the URL-parameter path with a single crafted page load, then clear cookies. If the cookie path is in scope, set a unique synthetic marker and verify whether the banner renders it on subsequent loads.
- Capture the script URL/version, relevant privacy-center HTML-description setting if visible, input vector (`fides_description` parameter/global/cookie), rendered DOM sink, and whether the issue affects authenticated origins or shared subdomains.

### Froxlor API 2FA-boundary checks

- Use a disposable account with TOTP enabled and a dedicated API key/secret. Do not test with real customer or administrator secrets.
- First prove that the web UI login requires a TOTP challenge after password submission. Then send a minimal API request authenticated only with `API_KEY:API_SECRET` and verify whether it succeeds without any TOTP phase.
- Keep the API action read-only where possible, such as a version/status or self-scope listing endpoint. Do not modify domains, mailboxes, DNS, FTP shells, or customer data unless the engagement explicitly authorizes state changes.
- Record API-enabled settings, account type, 2FA state, API key scope/expiry, endpoint path, HTTP status, and the contrast between UI TOTP enforcement and API acceptance.

### Ironic Python Agent image-boundary checks

- Validate only in a lab or customer-approved OpenStack bare-metal test project. Do not deploy malicious images to shared production provisioning pools.
- Build a disposable image that plants a benign marker in the `grub-install` execution path or equivalent lab harness indicator. The goal is to prove that IPA resolves executable functionality from inside the image chroot, not to gain persistence or tamper with real nodes.
- Capture IPA version, image format, deployment path, node isolation, logs showing the marker execution, and cleanup evidence for the test node.
- Stop at controlled execution proof. Avoid reading host secrets, altering bootloaders beyond the lab marker, or leaving modified images registered after validation.

## Reporting heuristics

- Lead with the boundary crossed: visitor-controlled banner text to executable DOM, API key-only authentication to 2FA-protected operations, or tenant image content to provisioning-agent execution.
- Include preconditions prominently so the finding is reproducible and not a generic version report.
- Show safe before/after controls: Fides plain-text or HTML-disabled behavior, Froxlor UI TOTP requirement versus API acceptance, and Ironic patched/lab behavior where executable lookup no longer trusts the image path.
- Keep sensitive material out of artifacts. Redact API secrets, tenant identifiers, OpenStack project names, and any accidental tokens in browser or provisioning logs.

## Notes on skipped and already-represented items from this scan

- samlify signed-attribute XML injection and OpenMetadata `TEST_CONNECTION` credential disclosure were already covered in the May 21 SAML/MCP/metadata/render batch and were not duplicated.
- The current Flowise updated-advisory wave maps to previously published Flowise tenant/workflow, RCE, and credential-boundary pages.
- Guardrails AI package compromise, MVT backup path traversal, and Fabric chaincode log disclosure were marked processed for this run because they did not add a stronger offensive operator workflow than existing supply-chain, untrusted-artifact, or secret-log guidance.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, Disclosed, and CISA KEV had no separate new promotable deltas beyond items already represented in the wiki.
