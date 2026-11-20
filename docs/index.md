---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Etherpad's path sanitizer runs before the handler converts backslashes, so one anonymous `..%5C` GET on `/static/plugins/` reads `/etc/passwd`, `settings.json`, and `/proc/self/environ` with the admin password inside, and the plugin installer finishes the RCE chain (9.8, before 3.3.3, reverse proxies don't help, `%5C` passes through)**](alerts/2026-11-20-etherpad-static-handler-post-sanitizer-backslash-traversal-unauth-file-read-to-admin-rce-ghsa.md)
- [**The signature gate lives on only one promotion path: in Mareforma an unsigned claim converges with a signed peer and reaches REPLICATED trust, the search endpoint serves forged ESTABLISHED rows the query endpoint drops, and a post-signing Rekor block counts as transparency proof (5 GHSAs)**](alerts/2026-11-19-mareforma-coordinated-wave-signature-blind-convergence-verify-on-read-split-and-unsigned-rekor-metadata-ghsa.md)
- [**The Kotlin DSL sandbox is six sandboxes: TeamCity leaked through public reflection, boot classpath, script definitions, and two callbacks, while project viewers downloaded whole settings archives and guests pushed VCS labels with the server's stored credentials (82 GHSAs, before 2026.2.1 / 2026.1.5)**](alerts/2026-11-19-teamcity-coordinated-wave-kotlin-dsl-sandbox-escapes-viewer-credential-reads-and-guest-vcs-deputy-ghsa.md)
- [**Your fleet tokens are only as case-sensitive as the MySQL column: Fleet invite, email-change, MFA, and session tokens lived in `utf8mb4_unicode_ci` so any case-folded copy authenticates, and a team observer's live-query write into the session store lets a self-signed SAML response mint global admin (5 GHSAs)**](alerts/2026-11-19-fleet-coordinated-wave-case-insensitive-token-columns-session-store-saml-forgery-and-deprecated-enqueue-split-ghsa.md)
- [**The CSRF guard is the RCE: defunct Idunno.AntiCsrf deserializes your `__CSRFTOKEN` form field with an unkeyed `ObjectStateFormatter` at `PreRequestHandlerExecute`, so one anonymous POST to any `.aspx` with `__CSRFCOOKIE=1` runs code in `w3wp.exe`, no patch exists, and ITW exploitation is reported (CVE-2026-131914)**](alerts/2026-11-19-idunno-anticsrf-unkeyed-csrf-token-deserialization-anonymous-webforms-rce-cve-2026-131914.md)
- [**A restricted cert becomes host root: Incus entitlements check the project you name, so a sibling project missing `features.*` flags takes your `raw.dnsmasq` bridge, and appending the server certificate to your TLS chain authenticates you as a trusted peer (18 GHSAs, before 7.6.0)**](alerts/2026-11-19-incus-coordinated-wave-restricted-project-flag-escape-dnsmasq-root-execution-forged-tls-chain-and-migration-peer-traversal-ghsa.md)
- [**The row filter for hidden attributes lives only on the detail route: MISP's restSearch prefix matching enumerates an org-only attribute's value one character at a time, and eventCorrelations hands back full correlations for events you cannot view (5 GHSAs)**](alerts/2026-09-17-misp-cakephp-argv-phar-rce-sap-cds-mtxs-tenant-credentials-and-android-exported-activity-file-write-ghsa.md)
- [**The proxy dials whatever host your namespace renders into: temporal-proxy's templated upstream ships the upstream's static API key to a caller-chosen host, and pooling by rendered address mixes per-upstream credentials and encryption keys**](alerts/2026-09-21-temporal-internal-deputy-subprocess-provider-and-noobaa-presigned-copyobject-ghsa.md)
- [**The install invite nobody claimed: Atomic Server's `/setup` hands write access to the whole Drive to the first anonymous caller who brings their own key, and `/bookmark` fetches any URL because the dispatcher returns before the auth check (4 GHSAs, full PoCs)**](alerts/2026-11-18-atomic-server-wave-setup-invite-endpoint-dispatch-internalid-read-and-inline-download-ghsa.md)
- [**Five 9.8 BIG-IP RCEs each need one iRule command on the virtual server: inventory `PSC::ip_address`, `DNS::scrape`, `GENERICMESSAGE::route`, `MR::message`, `PEM::subscriber` per vserver, and forged `ssl_preread` values reroute NGINX stream traffic (22 GHSAs)**](alerts/2026-11-18-f5-bigip-nginx-coordinated-wave-irule-command-gated-tmm-rces-forged-stream-preread-and-rest-token-lifetime-ghsa.md)




