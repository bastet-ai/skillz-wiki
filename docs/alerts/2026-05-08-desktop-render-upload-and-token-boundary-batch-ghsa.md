# Desktop render, upload, and token-boundary batch

**Signal:** The **2026-05-08 19:15 UTC** advisory scan added a mixed but durable set of boundary failures across Electron renderers, model/admin UIs, backup portals, module updaters, parser resource limits, and enrollment handshakes.

## Advisory cluster

- **SiYuan Electron renderer RCE via tooltip XSS** — [GHSA-25rp-h46x-2hjm](https://github.com/advisories/GHSA-25rp-h46x-2hjm): incomplete fix for CVE-2026-34585; `decodeURIComponent`-driven `aria-label` tooltip rendering can reach Electron RCE. No patched version listed at advisory time.
- **open-webui stored XSS via model description** — [GHSA-gf5m-wcrh-7928](https://github.com/advisories/GHSA-gf5m-wcrh-7928): npm/pip `open-webui <= 0.8.12`; patch to `0.9.0+`.
- **Rdiffweb access-token impersonation** — [GHSA-v4gp-hf5j-4566](https://github.com/advisories/GHSA-v4gp-hf5j-4566): `rdiffweb < 2.10.6` allowed any valid or stolen token to act as other users. Patch to `2.10.6+`.
- **OpenSTAManager arbitrary module upload** — [GHSA-rm34-fg4m-39mw](https://github.com/advisories/GHSA-rm34-fg4m-39mw): `devcode-it/openstamanager <= 2.10-beta`; no patched version listed at advisory time.
- **HashiCorp Boundary worker enrollment TLS handshake DoS** — [GHSA-7x9r-wcgg-w86f](https://github.com/advisories/GHSA-7x9r-wcgg-w86f): patch Boundary to `0.19.5+`, `0.20.3+`, or `0.21.3+` depending on line.
- **justhtml parser DoS hardening** — [GHSA-r8cj-3554-33mr](https://github.com/advisories/GHSA-r8cj-3554-33mr): `justhtml < 1.18.0`; patch to `1.18.0+`.
- **phpseclib ASN.1 OID length duplicate/canonicalization update** — [GHSA-f2qx-66wf-wvvx](https://github.com/advisories/GHSA-f2qx-66wf-wvvx), withdrawn duplicate [GHSA-jr22-8qgm-4q87](https://github.com/advisories/GHSA-jr22-8qgm-4q87): patch `phpseclib/phpseclib` to `1.0.23+`, `2.0.47+`, or `3.0.36+` for this OID-length hardening path; see the newer parser/crypto phpseclib guidance for later patch floors where applicable.

## Triage

1. Prioritize Electron/desktop apps, AI/model admin UIs, backup portals, and module/plugin uploaders on developer or admin workstations.
2. Patch open-webui and Rdiffweb immediately; isolate or disable OpenSTAManager module-update upload paths until a fixed release is available.
3. For SiYuan, treat untrusted notebook content, imported docs, and synced workspaces as code-adjacent if Electron integration is enabled.
4. For Boundary, rate-limit worker enrollment endpoints and look for handshake spikes or enrollment failures from repeated sources.
5. For parser/resource issues, enforce input size, nesting, and time budgets before expensive decode/render steps.

## Hunt prompts

- Stored model descriptions, notebook labels, tooltips, backup labels, module metadata, or admin UI fields containing encoded HTML, event handlers, SVG, `javascript:`, or `decodeURIComponent` gadget payloads.
- Backup/admin actions where one user token performs operations or reads data for another account.
- Module update ZIPs, PHP files, or plugin archives uploaded outside expected maintenance windows.
- Boundary worker enrollment logs with repeated TLS failures, high CPU, or queue exhaustion.
- ASN.1/OID or HTML parser inputs that produce unusually high CPU, memory, or timeout rates.

## Durable controls

- Keep renderer content sanitized at every sink, not only at initial import; tooltips, titles, ARIA labels, markdown previews, and model descriptions are executable UI surfaces.
- Scope access tokens to an immutable subject and re-check subject/resource authorization server-side on every request.
- Treat plugin/module upload as code deployment: require admin MFA, signed artifacts, extension allowlists, unpack path controls, and post-upload scanning.
- Budget parser work before allocation and make malformed input cheap to reject.
- Separate worker enrollment/control-plane handshakes from public or attacker-reachable network paths where possible.
