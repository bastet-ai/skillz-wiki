---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**The row filter for hidden attributes lives only on the detail route: MISP's restSearch prefix matching enumerates an org-only attribute's value one character at a time, and eventCorrelations hands back full correlations for events you cannot view (5 GHSAs)**](alerts/2026-09-17-misp-cakephp-argv-phar-rce-sap-cds-mtxs-tenant-credentials-and-android-exported-activity-file-write-ghsa.md)
- [**The proxy dials whatever host your namespace renders into: temporal-proxy's templated upstream ships the upstream's static API key to a caller-chosen host, and pooling by rendered address mixes per-upstream credentials and encryption keys**](alerts/2026-09-21-temporal-internal-deputy-subprocess-provider-and-noobaa-presigned-copyobject-ghsa.md)
- [**The install invite nobody claimed: Atomic Server's `/setup` hands write access to the whole Drive to the first anonymous caller who brings their own key, and `/bookmark` fetches any URL because the dispatcher returns before the auth check (4 GHSAs, full PoCs)**](alerts/2026-11-18-atomic-server-wave-setup-invite-endpoint-dispatch-internalid-read-and-inline-download-ghsa.md)
- [**Five 9.8 BIG-IP RCEs each need one iRule command on the virtual server: inventory `PSC::ip_address`, `DNS::scrape`, `GENERICMESSAGE::route`, `MR::message`, `PEM::subscriber` per vserver, and forged `ssl_preread` values reroute NGINX stream traffic (22 GHSAs)**](alerts/2026-11-18-f5-bigip-nginx-coordinated-wave-irule-command-gated-tmm-rces-forged-stream-preread-and-rest-token-lifetime-ghsa.md)
- [**ArangoDB's auth gate reads the raw path, the router reads the decoded one: `/%5fapi/` walks past the underscore-namespace check and dispatches as superuser, exploited in the wild since September (critical 9.8, before 3.12.11)**](methodology/canonicalization-differentials-at-security-gates.md)
- [**A sanitizer verdict is not a clone verdict: `selectedcontent` clones an SVG script out of a selected option and the clone executes, solving the innerHTML-without-equals impossible lab in Safari 27.2**](methodology/xss-tag-name-payload-hiding-waf-bypass.md#november-18-2026-follow-up-selectedcontent-clones-an-svg-script-out-of-a-selected-option-and-the-clone-executes-solving-the-innerhtml-without-equals-impossible-lab)
- [**Your IdP is whatever the header says: CAST Imaging's `X-ISSUER-LOCATION` registers any OIDC issuer, so a realm you operate mints admin JWTs, and `/proc/self/environ` hands over the Keycloak and Postgres passwords (8 GHSAs)**](alerts/2026-11-18-cast-imaging-wave-issuer-header-idp-enrollment-proc-env-read-and-hardcoded-auth-token-ghsa.md)
- [**Any web page you visit can drive your local MCP tools: Supergateway's stdio-to-WebSocket bridge validates no Origin header, so a hostile site runs the MCP handshake and invokes your wrapped stdio tools with your privileges**](alerts/2026-10-01-mcp-gateway-session-client-browser-bridge-and-agent-prompt-injection-cluster-ghsa.md)
- [**Type the admin's email into a Google Pay checkout field and walk in with session cookies: Unzer and Trust Payments WooCommerce gateways mint `wp_set_auth_cookie` sessions from unvalidated identity inputs, one via `WP_Error` integer cast to user 1 (2 critical GHSAs)**](alerts/2026-09-23-woocommerce-payment-webhook-branch-and-amount-integrity-cluster-ghsa.md)
- [**Your install path can contain a bracket: Grav's unescaped glob counts zero users, so anonymous visitors mint themselves super admin**](alerts/2026-10-12-grav-coordinated-wave-derived-federated-credentials-2fa-lifecycle-gaps-and-nested-git-disclosure-ghsa.md#november-18-follow-up-third-grav-wave-an-unescaped-glob-in-the-account-count-gate-hands-anonymous-visitors-super-admin-and-the-flex-field-name-to-method-dispatch-deletes-every-account-17-ghsas-17537-2218)




