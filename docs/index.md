---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**A sanitizer verdict is not a clone verdict: `selectedcontent` clones an SVG script out of a selected option and the clone executes, solving the innerHTML-without-equals impossible lab in Safari 27.2**](methodology/xss-tag-name-payload-hiding-waf-bypass.md#november-18-2026-follow-up-selectedcontent-clones-an-svg-script-out-of-a-selected-option-and-the-clone-executes-solving-the-innerhtml-without-equals-impossible-lab)
- [**Your IdP is whatever the header says: CAST Imaging's `X-ISSUER-LOCATION` registers any OIDC issuer, so a realm you operate mints admin JWTs, and `/proc/self/environ` hands over the Keycloak and Postgres passwords (8 GHSAs)**](alerts/2026-11-18-cast-imaging-wave-issuer-header-idp-enrollment-proc-env-read-and-hardcoded-auth-token-ghsa.md)
- [**Any web page you visit can drive your local MCP tools: Supergateway's stdio-to-WebSocket bridge validates no Origin header, so a hostile site runs the MCP handshake and invokes your wrapped stdio tools with your privileges**](alerts/2026-10-01-mcp-gateway-session-client-browser-bridge-and-agent-prompt-injection-cluster-ghsa.md)
- [**Type the admin's email into a Google Pay checkout field and walk in with session cookies: Unzer and Trust Payments WooCommerce gateways mint `wp_set_auth_cookie` sessions from unvalidated identity inputs, one via `WP_Error` integer cast to user 1 (2 critical GHSAs)**](alerts/2026-09-23-woocommerce-payment-webhook-branch-and-amount-integrity-cluster-ghsa.md)
- [**Your install path can contain a bracket: Grav's unescaped glob counts zero users, so anonymous visitors mint themselves super admin**](alerts/2026-10-12-grav-coordinated-wave-derived-federated-credentials-2fa-lifecycle-gaps-and-nested-git-disclosure-ghsa.md#november-18-follow-up-third-grav-wave-an-unescaped-glob-in-the-account-count-gate-hands-anonymous-visitors-super-admin-and-the-flex-field-name-to-method-dispatch-deletes-every-account-17-ghsas-17537-2218)
- [**The share link's row filter lives only on the list route: NocoDB's read-by-id, relation, and attachment-download endpoints let anonymous holders enumerate every excluded record**](alerts/2026-11-13-nocodb-wave-empty-admin-bootstrap-account-wide-tokens-and-unmasked-credential-reads-ghsa.md#november-18-follow-up-second-nocodb-wave-the-shared-view-row-filter-lives-only-on-the-list-path-and-oauth-tokens-are-forged-with-the-instance-session-secret-43-ghsas-cve-2026-130687-through-cve-2026-130731)
- [**Your `.dir-locals.el` runs before Emacs checks it: one hostile repo folder, one file open, arbitrary Elisp as the user (Emacs 31.1)**](alerts/2026-06-12-esbuild-mise-tomcat-radius-boundary-batch-ghsa.md#november-18-follow-up-emacs-calls-your-dir-localsel-auto-mode-alist-function-before-validating-it-cve-2026-131959-ghsa-5hqm-5j9g-jhcr-high-emacs-311-302-unaffected)
- [**The IPAM console relays your keystrokes to every managed Windows node: DDI Central blocked-domain and IPv6 scope-id legs turn low-priv console auth into agent-side command execution**](alerts/2026-09-21-management-plane-config-writes-toctou-onboarding-race-and-flat-authz-drift-ghsa.md#november-18-follow-up-manageengine-ddi-central-two-config-value-becomes-shell-command-legs-where-the-console-relays-your-input-to-every-managed-windows-node-cve-2026-95645-ghsa-gwgc-hqh6-hx9r-cve-2026-95643-ghsa-gp5r-5mmq-pgr6-critical-builds-below-6500)
- [**One member-role API call writes files on the volume host: Cinder's LIO driver builds target config paths from your IQN, traversal and all**](alerts/2026-10-08-openstack-mistral-orchestration-plane-built-in-exec-sharing-lifecycle-and-policy-free-maintenance-ghsa.md#november-18-follow-up-cinders-lio-iscsi-target-driver-builds-config-paths-from-the-callers-iqn-a-member-role-os-initialize_connection-writes-files-anywhere-on-the-volume-host-cve-2026-131920-ghsa-xrpq-2pv7-g346-medium-before-2911)
- [**The concealment plugin unmasks itself: Hide My WP Ghost's leftover debug branch hands anonymous callers your hidden login URL, a multisite subsite admin gets network-wide SQL, and WPvivid restores instantiate Subscriber-planted PHP objects**](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md#november-18-0630z-follow-up-the-concealment-plugin-unmasks-itself-via-a-leftover-debug-branch-a-subsite-admin-gets-network-wide-sql-and-backup-restore-instantiates-subscriber-planted-objects-7-legs-folded)




