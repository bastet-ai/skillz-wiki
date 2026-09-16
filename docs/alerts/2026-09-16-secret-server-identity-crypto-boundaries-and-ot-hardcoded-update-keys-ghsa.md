# Secret Server identity/crypto trust cluster + hardcoded update-channel keys in OT software (5 GHSAs)

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-09-16 (waves published 2026-09-16T00:31Z–03:31Z).

Two compact clusters with reusable axes for engagements that touch **secrets vaults** and **appliance/OT update channels**:

1. **The vault itself has identity and crypto boundaries.** Delinea Secret Server published three critical advisories in one wave: a padding oracle reachable by an authenticated-but-low-privilege user, a SAML impersonation path, and a link-driven script-execution sink. Secrets managers are "assume breach" assets in red-team scope: the durable workflow is to treat the vault UI as just another web app and to verify that SAML assertions are bound to the destination tenant/user and that stored-secret crypto is authenticated (AEAD) rather than encrypt-then-trust.
2. **Hardcoded cryptographic keys in update controllers.** Wärtsilä FOS-Onboard (marine operations software) shipped a hardcoded server key in the Update Controller component and a hardcoded client authentication key in its robot testing framework. When an update or automation channel authenticates with a key embedded in distributed software, the key is public — anyone can forge or mitm that channel. For any vendor appliance/OT software you assess, extracting bundled keys from the update/automation path is a first-class check.

## Advisory table

| GHSA | CVE | Sev. | Boundary |
| --- | --- | --- | --- |
| [GHSA-grw7-x4gw-45r5](https://github.com/advisories/GHSA-grw7-x4gw-45r5) | CVE-2026-15638 | critical | "An unauthenticated user with access to Secret Server could leverage a padding oracle to decrypt or encrypt data using one of the server's cryptographic keys" (CWE-327, risky crypto mode). The key is not exposed, but the oracle grants an attacker the vault's own encryption/decryption capability on chosen data — classic CBC-style padding oracle at a secrets store. |
| [GHSA-43cm-c736-gj85](https://github.com/advisories/GHSA-43cm-c736-gj85) | CVE-2026-15640 | critical | "Under certain conditions a valid SAML IdP response may be used to impersonate another Secret Server user" (CWE-290, spoofing). Assertion-to-identity binding gap: a legitimate assertion for one principal can be replayed/re-targeted to another user. |
| [GHSA-5jwp-q2ph-6mgc](https://github.com/advisories/GHSA-5jwp-q2ph-6mgc) | CVE-2026-15639 | critical | "An attacker can craft a malicious link that, if used by a legitimate user, may cause the user's browser to run JavaScript supplied by the attacker" (XSS). Browser-resident XSS on a vault UI means the vault session is the pivot. |
| [GHSA-xr64-qq65-vf4r](https://github.com/advisories/GHSA-xr64-qq65-vf4r) | CVE-2026-78225 | critical (CVSS 9.0) | Hardcoded cryptographic **server** key in the Wärtsilä FOS-Onboard deployer-ng **Update Controller** component — the update channel's trust anchor is embedded in shipped software. |
| [GHSA-j2xg-7hvh-hxm5](https://github.com/advisories/GHSA-j2xg-7hvh-hxm5) | CVE-2026-81855 | critical (CVSS 9.1) | Hardcoded cryptographic **client authentication** key in the Wärtsilä FOS-Onboard robot testing framework — client-auth trust based on a distributable secret. |

Adjacent, tracked without publication from the same waves: [@jitsi/electron-sdk](https://github.com/advisories/GHSA-q3gq-fmhq-w6pr) before 10.0.5 (CVE-2026-92299, high) exposes `getDesktopSources()` via `contextBridge` with no active `getDisplayMedia()` picker, so any script in a meeting page silently enumerates screens/windows with thumbnails — a durable Electron/IPC axis (privileged IPC route reachable without the user-gesture gate) already covered by the existing desktop-client IPC pages; the Chrome 153.0.8010.47 memory-safety GHSA mirror wave (no public exploit path); Arista EOS IS-IS/VRRP/DHCP/MLAG protocol DoS set; Netcore NR255/NR268 firmware bundle (single-product CGI command-construction, axis already on appliance pages); mySCADA myPRO unauth command API and hardcoded-key records (OT appliance, tracked); VeloCloud Edge input-validation and update-signature records (vendor embargo — the update-integrity axis above applies); Microsoft Edge (Chromium) memory-safety records; Oracle GraalVM CPU patches; a2ui/ag-ui/vLLM sparse entries; Cotonti `unserialize()`; Podman `podman load` tar follow-up; adm-zip decompression limits; GIMP file-psd; QloApps back-office XSS; Devolutions log disclosure; rejected-CVE records.

## Why this is worth an operator page

- **Secrets vaults are the highest-value web app in the estate, and operators rarely test them as such.** The padding-oracle record is the reminder: server-side crypto that answers "did this decrypt validly?" hands you a decryption oracle on the exact data class you were hired to protect. Same for SAML binding checks on the vault's own SSO.
- **Hardcoded update-channel keys collapse the vendor supply chain to a network-position problem.** If the update controller trusts a key that ships inside the product, "authorized update path" = "anyone who captured the binary." Pair with the existing archive/update-integrity workflows.
- Both clusters give clean positive/negative test shapes that never require touching real secrets.

## Validation workflow (authorized scope only)

!!! warning "Synthetic data and lab instances only"
    Never decrypt or re-encrypt real stored secrets, never replay a live user's SAML assertion, never XSS a production vault session, never intercept a live OT update channel. Use lab-instanced vaults with synthetic secret rows, your own IdP, and owned update endpoints.

1. **Vault crypto oracle check (lab only).** With a low-privilege lab account, enumerate every endpoint that returns encrypt/decrypt-or-validity behavior on attacker-influenced ciphertext (import/export, backup restore, folder-key paths). Record timing/error differentials per ciphertext modification. Evidence = a decision table (ciphertext variant → response class), never plaintext of a real secret.
2. **SAML binding parity.** With a disposable IdP and two lab users, test whether an assertion minted for user A is accepted for user B across each SSO entry route (SP-initiated, IdP-initiated, token-exchange siblings). Check audience, recipient, and Subject-to-local-user binding separately. Stop at an identity-mapping decision table.
3. **Vault XSS grammar sweep.** Treat the vault UI like any app: reflected/stored/mXSS on search, folder names, secret display names, and link-shaped entry points (the advisory confirms a malicious-link → script sink exists). Report only with harmless DOM markers in your own session.
4. **Update-channel key extraction (authorized product assessments).** For appliance/OT software in scope, inspect the shipped update/automation components for embedded key material (search bundles for PEM blobs, hardcoded public-key constants, signature-verification call sites). Demonstrate that the extracted key verifies a *synthetic* manifest against the product's own verifier — never deliver a manifest to a live system.
5. Report decision tables and byte-level evidence; do not claim decryption of customer data or firmware update takeover without a lab end-to-end proof.
