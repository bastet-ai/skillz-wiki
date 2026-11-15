---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Cyrus SASL SRP no-password login: send A = N, the shared secret becomes zero, log in as anyone**](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md#november-15-follow-up-cyrus-sasl-srp-server-accepts-a-n-the-shared-secret-collapses-to-zero-and-any-existing-user-logs-in-with-no-password-cve-2026-129483-ghsa-h9fw-9v74-m2cr-critical-93-through-2128)
- [**OkHttp pinning bypass on trailing-dot hostnames: an allowlist miss that skips the check instead of failing it**](methodology/canonicalization-differentials-at-security-gates.md#november-15-follow-up-okhttp-certificatepinner-skips-the-pin-check-on-trailing-dot-hostnames-cve-2026-129482-ghsa-p22c-cv6w-qc6x-medium-through-551)
- [**Apache Shiro any-password login: auth cache hits skip the LDAP bind and the default matcher checks nothing**](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md#november-15-follow-up-apache-shiro-defaultldaprealm-caches-the-login-but-verifies-nobody-on-cache-hits-any-password-works-while-the-entry-is-warm-cve-2026-129349--ghsa-3j37-vw7v-fxxw-critical-all-versions-through-300-fixed-301)
- [**Give WP Peer-to-Peer unauth RCE: two 7.5 advisories that name each other, SQLi for credentials plus unauth upload for code**](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md#november-15-1231z-follow-up-give-wp-two-advisory-chain-an-unauth-write-leg-and-an-unauth-sqli-leg-that-advertise-each-other-as-rce-2-legs-folded)
- [**dufs WebDAV COPY writes over files you're not allowed to delete: the upload-only verb that is secretly a delete**](alerts/2026-09-18-nextcloud-app-layer-authority-drift-circles-keyid-ssrf-webdav-locks-and-deck-config-ghsa.md#november-15-follow-up-dufs-webdav-copy-an-upload-permission-verb-that-quietly-performs-a-delete-ghsa-3vw8-v548-fw83-cve-2026-129355-medium-dufs-0460-fixed-0470)
- [**Dokploy root RCE from a low-priv member: a saved `serviceName` runs as root when the backup cron fires**](alerts/2026-06-22-glances-opendj-spinnaker-control-plane-boundaries-ghsa.md#november-14-follow-up-dokploy-a-low-priv-org-member-seeds-servicename-through-trpc-and-the-scheduled-backup-runs-it-as-root-on-the-docker-socket-host)
- [**Shipo unauth admin takeover: cookie parsed for identity but never signature-verified, route gate fooled by a query string**](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md#november-14-1531z-follow-up-shipo--180-cookie-parsed-for-identity-but-never-verified-for-integrity-and-a-substring-route-gate-that-any-query-string-escapes-cve-2026-19907--ghsa-8269-9p52-9cvv-critical-98)
- [**Fluent Forms storage plugin unauth webshell: the Google Drive filename decides where the file lands**](alerts/2026-09-19-wordpress-shortcode-execution-hidden-field-upload-and-encrypted-blob-dispatch-ghsa.md#november-14-1531z-follow-up-cloud-storage-manager-for-fluent-forms--120-two-ungated-rest-endpoints-plus-the-cloud-providers-filename-decide-where-a-file-lands-on-disk-cve-2026-120522--ghsa-7rh5-mv9f-p27q-critical-98)
- [**APISIX wave (7 GHSAs): upstream trusts decrypted-identity headers the gateway never issued**](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md#november-14-follow-up-apache-apisix-seven-leg-gateway-wave-forged-decrypted-identity-headers-fallback-residue-any-of-scopes-and-out-of-contract-mcp-calls-7-ghsas-published-nov-13-1832z-fixed-3200)
- [**AutomatorWP unauth admin takeover: a blank Update-User target takes its victim from the webhook payload**](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md#november-14-0931z-follow-up-webhook-automation-relay-hands-the-update-user-target-to-the-attacker-and-a-bundled-update-checker-makes-the-plugin-authors-server-the-update-authority-2-legs-folded)


