---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**The install invite nobody claimed: Atomic Server's `/setup` hands write access to the whole Drive to the first anonymous caller who brings their own key, and `/bookmark` fetches any URL because the dispatcher returns before the auth check (4 GHSAs, full PoCs)**](alerts/2026-11-18-atomic-server-wave-setup-invite-endpoint-dispatch-internalid-read-and-inline-download-ghsa.md)
- [**Five 9.8 BIG-IP RCEs each need one iRule command on the virtual server: inventory `PSC::ip_address`, `DNS::scrape`, `GENERICMESSAGE::route`, `MR::message`, `PEM::subscriber` per vserver, and forged `ssl_preread` values reroute NGINX stream traffic (22 GHSAs)**](alerts/2026-11-18-f5-bigip-nginx-coordinated-wave-irule-command-gated-tmm-rces-forged-stream-preread-and-rest-token-lifetime-ghsa.md)
- [**ArangoDB's auth gate reads the raw path, the router reads the decoded one: `/%5fapi/` walks past the underscore-namespace check and dispatches as superuser, exploited in the wild since September (critical 9.8, before 3.12.11)**](methodology/canonicalization-differentials-at-security-gates.md)
- [**A sanitizer verdict is not a clone verdict: `selectedcontent` clones an SVG script out of a selected option and the clone executes, solving the innerHTML-without-equals impossible lab in Safari 27.2**](methodology/xss-tag-name-payload-hiding-waf-bypass.md#november-18-2026-follow-up-selectedcontent-clones-an-svg-script-out-of-a-selected-option-and-the-clone-executes-solving-the-innerhtml-without-equals-impossible-lab)
- [**Your IdP is whatever the header says: CAST Imaging's `X-ISSUER-LOCATION` registers any OIDC issuer, so a realm you operate mints admin JWTs, and `/proc/self/environ` hands over the Keycloak and Postgres passwords (8 GHSAs)**](alerts/2026-11-18-cast-imaging-wave-issuer-header-idp-enrollment-proc-env-read-and-hardcoded-auth-token-ghsa.md)
- [**Any web page you visit can drive your local MCP tools: Supergateway's stdio-to-WebSocket bridge validates no Origin header, so a hostile site runs the MCP handshake and invokes your wrapped stdio tools with your privileges**](alerts/2026-10-01-mcp-gateway-session-client-browser-bridge-and-agent-prompt-injection-cluster-ghsa.md)
- [**Type the admin's email into a Google Pay checkout field and walk in with session cookies: Unzer and Trust Payments WooCommerce gateways mint `wp_set_auth_cookie` sessions from unvalidated identity inputs, one via `WP_Error` integer cast to user 1 (2 critical GHSAs)**](alerts/2026-09-23-woocommerce-payment-webhook-branch-and-amount-integrity-cluster-ghsa.md)
- [**Your install path can contain a bracket: Grav's unescaped glob counts zero users, so anonymous visitors mint themselves super admin**](alerts/2026-10-12-grav-coordinated-wave-derived-federated-credentials-2fa-lifecycle-gaps-and-nested-git-disclosure-ghsa.md#november-18-follow-up-third-grav-wave-an-unescaped-glob-in-the-account-count-gate-hands-anonymous-visitors-super-admin-and-the-flex-field-name-to-method-dispatch-deletes-every-account-17-ghsas-17537-2218)
- [**The share link's row filter lives only on the list route: NocoDB's read-by-id, relation, and attachment-download endpoints let anonymous holders enumerate every excluded record**](alerts/2026-11-13-nocodb-wave-empty-admin-bootstrap-account-wide-tokens-and-unmasked-credential-reads-ghsa.md#november-18-follow-up-second-nocodb-wave-the-shared-view-row-filter-lives-only-on-the-list-path-and-oauth-tokens-are-forged-with-the-instance-session-secret-43-ghsas-cve-2026-130687-through-cve-2026-130731)
- [**Your `.dir-locals.el` runs before Emacs checks it: one hostile repo folder, one file open, arbitrary Elisp as the user (Emacs 31.1)**](alerts/2026-06-12-esbuild-mise-tomcat-radius-boundary-batch-ghsa.md#november-18-follow-up-emacs-calls-your-dir-localsel-auto-mode-alist-function-before-validating-it-cve-2026-131959-ghsa-5hqm-5j9g-jhcr-high-emacs-311-302-unaffected)




