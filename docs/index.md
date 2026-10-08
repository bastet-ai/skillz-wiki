---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [AsyncHttpClient coordinated wave (10 GHSAs) — stale-target replay writes one host's request+credentials into another host's valid TLS tunnel (critical), Digest-no-nonce→Basic cleartext downgrade, NTLM/SPNEGO pool-key identity crossover, plaintext HTTP plants/overwrites/deletes Secure cookies, `Domain=co.uk` public-suffix residual; client-side credential-crossing probe kit + fix-history version fingerprinting (Oct 8 17:1xZ)](alerts/2026-10-08-asynchttpclient-coordinated-wave-client-side-credential-crossing-replay-digest-downgrade-and-cookie-store-failures-ghsa.md)

- [IBM DataPower Gateway coordinated wave (~36 GHSAs) — unauthenticated heap-overflow RCE legs, RFC2047 encoded-word parser OOB write, empty-password LDAP admin bypass, XXE on the XML appliance, WS-signature validation bypass, band-gated WebUI XSS; header/MIME-parser probe battery + empty-password appliance test + edition-fingerprint decision table (Oct 8 15:3xZ)](alerts/2026-10-08-ibm-datapower-gateway-coordinated-wave-preauth-parser-overflows-empty-password-ldap-and-signature-trust-ghsa.md)

- [hMailServer coordinated wave — Windows COM service with zero DCOM ACLs (any local login = service-account file read/write + queue mail as any sender), loopback REST admin API brute-forced by DNS-rebinding page (no Host check, no local throttling), root update helper taking its signature-verifier from a service-writable file, DANE/DANE-TA fail-open downgrades, webmail decrypt-then-blob XSS + untrusted signer-cert reply-encryption poisoning (Oct 8 12:3xZ)](alerts/2026-10-08-hmailserver-coordinated-wave-local-com-privesc-loopback-rebinding-and-mail-security-downgrade-ghsa.md)

- [Brocade Fabric OS SAN management-plane wave — in-band Fibre Channel CT peer-switch auth bypass (no credentials: password reset/reboot/firmware push), RADIUS-VSA/directory-claim root role binding, read-only opcode RBAC bypass, header-only internal-endpoint gate + Host-header IP-ACL bypass, cross-logical-switch MAPS dump, AD-compromise-to-switch-RCE session-verification cmdi, SNMPv3/IKEv2-UDP500/web-daemon unauthenticated overflow surface (Oct 8 03:31Z)](alerts/2026-10-08-brocade-fabric-os-san-fabric-management-plane-trust-wave-ghsa.md)

- [Splunk Enterprise coordinated wave — 9.8 unauthenticated Patroni sidecar OS command execution on search head cluster members, search-job cross-user query/results disclosure, SPL2 filter SQLi, Secure Gateway sign-anything oracle, raw-config scripted-lookup capability miss; second Splunk sidecar RCE leg (Oct 7 21:3xZ)](alerts/2026-10-07-splunk-enterprise-coordinated-wave-sidecar-rce-job-tenancy-and-signing-oracles-ghsa.md)

- [Cisco 35-GHSA coordinated review dump — NGOAM VXLAN/MPLS/SRv6 OAM unauthenticated root RCE cluster (feature-enabled = attack surface, `show running-config` fingerprint), NX-API root RCE, Cisco License On-Prem CVSS 10.0 forgotten licensing appliance; GHSA review-dumps = pointers to vendor advisories, not sources (Oct 7 18:32Z)](alerts/2026-10-07-cisco-coordinated-review-dump-ngoam-management-plane-and-license-appliance-ghsa.md)

- [Backstage seven-GHSA wave — TechDocs `mkdocs.yml` sanitizer allow-list misses (`extra_templates`, `pymdownx.snippets` base_path/url_download) → repo-commit-to-backend RCE, Scaffolder `order=` secret oracle, task event/log credential reflection (Oct 7 16:2xZ)](alerts/2026-10-07-backstage-techdocs-sanitizer-allowlist-and-scaffolder-order-oracle-wave-ghsa.md)

- [Veeam Backup & Replication wave — Backup Viewer→SYSTEM RCE via Mount Service deserialization, EM master-key tamper, Cloud Connect tenant→provider arbitrary file read, AAP cleartext creds in guest logs; lowest-tier backup-role audit rule (Oct 7 11:1xZ)](alerts/2026-10-07-veeam-br-cloud-connect-backup-plane-role-and-boundary-wave-ghsa.md)

- [HPE ClearPass + AOS-S coordinated wave — unauthenticated deserialization/format-string/SQLi/auth-bypass ladder on the NAC management plane, path-traversal role oracle, OnGuard agent fleet as second network-facing surface, ArubaOS-Switch wired sibling; pre-auth-parse-is-the-boundary rule (Oct 6 21:3xZ)](alerts/2026-10-07-hpe-clearpass-aos-s-unauth-primitive-ladder-nac-trust-boundaries-ghsa.md)

- [Coraza WAF evasion wave — `SecArgumentsLimit` silent-drop ARGS bypass (94% at 10k args), truncated-multipart 200003 voiding, Native audit-log CRLF forgery; WAF fingerprint via drop-behavior differentials (Oct 6 20:3xZ)](alerts/2026-10-06-coraza-waf-evasion-wave-argument-limit-silent-drop-multipart-truncation-and-audit-log-forgery-ghsa.md)

