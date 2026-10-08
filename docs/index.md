---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [OpenStack Mistral orchestration-plane wave — `std.ssh_proxied` proxy_command = arbitrary executor command execution with DEFAULT config from any project member; policy-free `/v2/maintenance` cross-tenant PAUSED kill-switch; resolve-then-write cross-project rewrite + name-collision resource adoption; owner-blind owner-undeletable share re-grants — orchestrator action-catalog audit + share-lifecycle revoke battery (Oct 8 19:1xZ)](alerts/2026-10-08-openstack-mistral-orchestration-plane-built-in-exec-sharing-lifecycle-and-policy-free-maintenance-ghsa.md)

- [Malcolm NSM stack wave — Lua RBAC reads raw percent-encoded URI while nginx routes decoded (`/%68tadmin.php`); case-mismatch fall-through to the only unauthenticated proxy location with trusted `X-Forwarded-User`; unauth kiosk `script_call` + wildcard CORS = CSRF log-wipe; vendored FilePond fetch-any-URL with transfer-ID readback; arkime-live 8005 direct-connect forged identity + hardcoded secret — reverse-proxy multi-parser diff battery (Oct 8 19:1xZ)](alerts/2026-10-08-malcolm-nsm-stack-reverse-proxy-composition-wave-rbac-byte-vs-route-forged-identity-headers-and-fetch-anywhere-uploader-ghsa.md)

- [Handlebars template-injection triple (fixed 4.7.10) — 9.8 AST-input validator bypass: JSON-shaped `Program` AST reaches `compile()` and `blockParams.length` runs at render with default options; `Function.prototype.constructor` own-property defeats the sandbox deny-list (RCE with `allowProtoMethodsByDefault`); `precompile()` emits raw `</script>` breaking out of inline script embedding — validator-coverage-vs-compiler-consumption + own-property-twins + per-embedding-context escaping rules (Oct 8 18:1xZ)](alerts/2026-10-08-handlebars-template-injection-triple-ast-validator-bypass-own-property-denylist-and-script-breakout-ghsa.md)

- [AsyncHttpClient coordinated wave (10 GHSAs) — stale-target replay writes one host's request+credentials into another host's valid TLS tunnel (critical), Digest-no-nonce→Basic cleartext downgrade, NTLM/SPNEGO pool-key identity crossover, plaintext HTTP plants/overwrites/deletes Secure cookies, `Domain=co.uk` public-suffix residual; client-side credential-crossing probe kit + fix-history version fingerprinting (Oct 8 17:1xZ)](alerts/2026-10-08-asynchttpclient-coordinated-wave-client-side-credential-crossing-replay-digest-downgrade-and-cookie-store-failures-ghsa.md)

- [IBM DataPower Gateway coordinated wave (~36 GHSAs) — unauthenticated heap-overflow RCE legs, RFC2047 encoded-word parser OOB write, empty-password LDAP admin bypass, XXE on the XML appliance, WS-signature validation bypass, band-gated WebUI XSS; header/MIME-parser probe battery + empty-password appliance test + edition-fingerprint decision table (Oct 8 15:3xZ)](alerts/2026-10-08-ibm-datapower-gateway-coordinated-wave-preauth-parser-overflows-empty-password-ldap-and-signature-trust-ghsa.md)

- [hMailServer coordinated wave — Windows COM service with zero DCOM ACLs (any local login = service-account file read/write + queue mail as any sender), loopback REST admin API brute-forced by DNS-rebinding page (no Host check, no local throttling), root update helper taking its signature-verifier from a service-writable file, DANE/DANE-TA fail-open downgrades, webmail decrypt-then-blob XSS + untrusted signer-cert reply-encryption poisoning (Oct 8 12:3xZ)](alerts/2026-10-08-hmailserver-coordinated-wave-local-com-privesc-loopback-rebinding-and-mail-security-downgrade-ghsa.md)

- [Brocade Fabric OS SAN management-plane wave — in-band Fibre Channel CT peer-switch auth bypass (no credentials: password reset/reboot/firmware push), RADIUS-VSA/directory-claim root role binding, read-only opcode RBAC bypass, header-only internal-endpoint gate + Host-header IP-ACL bypass, cross-logical-switch MAPS dump, AD-compromise-to-switch-RCE session-verification cmdi, SNMPv3/IKEv2-UDP500/web-daemon unauthenticated overflow surface (Oct 8 03:31Z)](alerts/2026-10-08-brocade-fabric-os-san-fabric-management-plane-trust-wave-ghsa.md)

- [Splunk Enterprise coordinated wave — 9.8 unauthenticated Patroni sidecar OS command execution on search head cluster members, search-job cross-user query/results disclosure, SPL2 filter SQLi, Secure Gateway sign-anything oracle, raw-config scripted-lookup capability miss; second Splunk sidecar RCE leg (Oct 7 21:3xZ)](alerts/2026-10-07-splunk-enterprise-coordinated-wave-sidecar-rce-job-tenancy-and-signing-oracles-ghsa.md)

- [Cisco 35-GHSA coordinated review dump — NGOAM VXLAN/MPLS/SRv6 OAM unauthenticated root RCE cluster (feature-enabled = attack surface, `show running-config` fingerprint), NX-API root RCE, Cisco License On-Prem CVSS 10.0 forgotten licensing appliance; GHSA review-dumps = pointers to vendor advisories, not sources (Oct 7 18:32Z)](alerts/2026-10-07-cisco-coordinated-review-dump-ngoam-management-plane-and-license-appliance-ghsa.md)

- [Backstage seven-GHSA wave — TechDocs `mkdocs.yml` sanitizer allow-list misses (`extra_templates`, `pymdownx.snippets` base_path/url_download) → repo-commit-to-backend RCE, Scaffolder `order=` secret oracle, task event/log credential reflection (Oct 7 16:2xZ)](alerts/2026-10-07-backstage-techdocs-sanitizer-allowlist-and-scaffolder-order-oracle-wave-ghsa.md)
