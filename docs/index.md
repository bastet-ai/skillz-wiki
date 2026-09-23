---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**HTTP/3 fuzzing, race, and downgrade testing with Turbo Intruder (Sept 23 methodology)**: PortSwigger's Sept-23 release adds an HTTP/3 engine to Turbo Intruder + an HTTP/3 Adapter for all of Burp — durable operator workflow: **two tighter race primitives** (QUIC **single-datagram attack** = whole race group in one receive turn; **QPACK blocked-stream orchestration** = park-and-release deterministic races, gateMode verdict table localizes the window); **kettled HTTP/3 requests** with `^~`/`^s` escapes inject bytes that only decode after the edge's **H3→HTTP/1.1 downgrade re-serialization** (`Transfer-Encoding: chunked` past a pseudo-header-validating front end) + `:authority`/`:scheme` pseudo-header overrides vs SNI/transport = origin-routing tuple mismatch; **HTTP/3-only targets** become testable via the Adapter (`X-Http3: 1` explicit mode) — treat H3 as a separate implementation and diff H3-vs-TCP behavior per route (edge security layer present on one transport only = finding); SVCB/HTTPS-record + Alt-Svc fingerprinting, AUTO-vs-BURP engine rule (**never AUTO for desync**), request/response minimization (`Range: bytes=-1`), and the volume-safety boundary (100k–180k RPS is an availability event, not impact). Same wave folded: **WPGraphQL `updatePost` collection-vs-object capability drift** (Contributor publishes without `publish_posts`; sibling `createPost` has the missing check — REST-vs-GraphQL parity battery = the finding + negative control) onto the Sept 19 WP page; **Plone Classic portlet TALES injection** (9.9, any registered user's personal dashboard = code exec — self-service default role maps as SSTI footholds, inert expression-marker probes) onto the Sept 20 template-RCE page. Tracked without publication: REDAXO XSS/CSRF medium singles, Plug quadratic-parse DoS, Zapros decompression DoS pair. KEV catalog moved to 2026.09.23 (1721, entry set unchanged — Sept-22 four already processed)](methodology/http3-turbo-intruder-race-and-downgrade-testing.md)

- [**Document-viewer + desktop-update surface cluster — Foxit PDF pack, Tauri manifest downgrade, OEM localhost listeners (Sept 23)**: ~40-GHSA Foxit wave promoted as a durable audit playbook: **incrementally-updated PDFs keep a valid signature badge over altered visible content** (CVE-2026-91814 — the signature verifies one copy, the viewer renders another; sweep appended-segment + xref-repoint mutations on any signed-document validator; UI badge vs render is the verdict, not "does it validate"); **secure-reading-mode permission verification missing → crafted PDF triggers external SMB authentication with no prompt, leaking the user's NTLM hash** (91796 — every document-triggered network resolution is an NTLM-coercion primitive; the missing prompt is the finding); **PDF-JS interface omits spec-required attribute authorization → a malicious PDF reads other documents open in the same process** (91788 — per-document policy over a per-process object graph); **updater MITM via bypassable cert validation** (91812) + **package swap between download and privileged extraction** (91813) + updater/installer/daemon LPE trio — four-question updater checklist: transport pinning, **descriptor authenticity**, swap-window re-verification, privileged-helper hygiene. **Tauri updater second axis**: minisign covers the binary but the **manifest (version/URL/signature) is unsigned** and anti-rollback compares the **unsigned version field** → anyone in the manifest path forces install of an older signed release without the developer key (95625) — *authenticate the descriptor, not just the payload*; pairs with the Sept-22 webview `allowDowngrades` bug (two entry points, one component). **Acer NitroSense**: production build ships **Electron DevTools on localhost TCP 9993** (any local user → privileged-app JS → code exec) + **unauthenticated localhost MQTT WebSocket exposing ddsc RPC including `child_process.execSync()`** (50228/50227) — post-access endpoint recon: enumerate every localhost listener (OEM suites ship zero-auth loopback RPC; `GET /json/version` answering JSON = shipped DevTools); CGServiSign adds the web-content→local-service cmdi variant (15027). + folds: **Apache Doris FE meta service authenticates on client-supplied node info** → unauth internal cluster-metadata read (31377) onto the Sept 21 auth-precedence page (asserted vs proven peer identity); **Rename wp-login time-based SQLi via `log`** (93368 — core `wp_unslash()`es the username before `wp_login_failed`, inverting the handler's escaping contract: the auth-failure path is an unauth SQL sink) + **Getwid block-frontend `eval()` stored XSS** (5924) + **ACF7 DB shortcode lets Contributors read all form submissions** (6831) onto the Sept 19 WP page. Tracked: Foxit memory-safety remainder (~30; file-write traversals 91801/91797 flagged), BuildStream tar symlink, uniFLOW session retention, kernel singles. KEV unchanged (2026.09.22, 1721)](alerts/2026-09-23-document-viewer-and-desktop-update-surface-cluster-ghsa.md)

- [**Payment-gateway webhook branch integrity + client-trusted amount state — five-plugin WP/WC cluster (Sept 23)**: Premium Packages **never verifies PayPal webhook signatures** → unauth forged payment confirmations/cancellations for any known transaction id (CVE-2026-93511); Paymob verifies signatures on the payment branch but **not the card-token branch** → unauth card-token write on any account + account enumeration (87979), plus contributor-reachable gateway-config wipe (87981); Payment Plugins' order-ownership check **runs only when the PayPal order is already completed** → replay a victim's *approved-uncaptured* order id on your own checkout and the victim's funds are captured against your order (80342) — every `if (state == X) verify()` hides an unverified non-X path; Better Payment never re-derives amount server-side (77765); Points and Rewards claim handler validates neither amount nor caller → Subscriber self-credits unlimited points (93510). Axes: webhook signature coverage is **per-branch**, test every event-type leg with forged payloads; probe the **skip-condition** of conditional integrity checks across the state machine; amounts/rewards are server-derived or attacker-derived; opaque ids become credentials when verification is absent (report id structure/enumerability). + folds: WP OAuth Server **returns the most-recently-authenticated user's OIDC assertion** for any grant → Subscriber mint admin-signed identity for the whole SSO fleet (82843, two-account interleaved grant battery); Directorist wave = **fix-history recon** (incomplete fix of CVE-2023-1889 via unpatched deletion path + 8.9.1 regression of a correctly-fixed 8.8.1 endpoint — re-run old CVEs, bisect ranges); Easy Hide Login leaks the secret slug via always-public reset flow (satellite-route fuzzing); YAHMAN remote-file cache = unauth PHP write→RCE (fetch-then-store *write leg* is the sink); Forminator anonymous mail-send carries site template + attacker link, plugin-minted replayable token; WC Fields Factory subscriber arbitrary post-meta write incl. product pricing rules. LMDeploy `load_image()` VL SSRF with 0.0.0.0 bind + auth-off defaults onto the SGLang page](alerts/2026-09-23-woocommerce-payment-webhook-branch-and-amount-integrity-cluster-ghsa.md)

- [**GHES appliance surface: port-blind SSRF with timing oracle → RCE, sanitize-then-rewrite XSS, name-scoped diff-token IDOR (Sept 22)**: notebook viewer validated URL **scheme+host but not port** → same-appliance internal services reachable with a guard-passing URL; **no response body but response timing leaked instance secrets character-by-character**, then the secret chained into an internal-service interaction = **unauthenticated appliance RCE** (CVE-2026-77987, critical; private-mode posture decides auth requirement) — durable axes: **port is a first-class SSRF validation dimension and approved-host-plus-foreign-port is the tuple guards miss**, and **latency is an extraction oracle when bodies are withheld** (generalizes the Sept 17 outer-status oracle). Markdown pipeline **rewrote quotes in already-sanitized HTML and rendered the rewritten copy unsanitized** → attribute injection, same-origin JS gadgets defeat CSP, payload propagates through the victim’s write access (CVE-2026-77912) — post-sanitizer transformations invalidate the sanitizer verdict; fuzz canaries that only activate after rewriting. Raw-diff tokens scoped to **repo name + PR number instead of unique id** → create a colliding repo/PR, replay your own token against the private target (CVE-2026-75101) — **name-unique scope keys = collision IDOR generator**. + two same-wave folds: **Skipper OPA body-authz third variant** (CVE-2026-86043) onto the July 8 page — the recommended `truncated_body == false` guard itself fails open on chunked/H2 because the flag is only computed when content-length exists: test vendor mitigations with the flag **absent vs false vs true**; **Vaultwarden revoked/pending members keep org-cipher access** (CVE-2026-95814) onto the Sept 21 auth-precedence page — membership-status enum missing from access-query predicates. Tracked detail-free: SolarWinds Observability Self-Hosted unauth RCE pair (28324/28325), Rockwell ALE ~10-GHSA cluster incl. default creds + unauth elevated file write, Unbound DNSKEY self-compression-pointer digest overflow (81642), Emacs read-symbol-shorthands RCE, OpenClaw iOS logged bearer keys, Mattermost OAuth-leg internal SSRF. KEV unchanged (catalog 2026.09.22, 1721); all blog feeds unchanged](alerts/2026-09-22-ghes-appliance-surface-port-blind-ssrf-timing-oracle-sanitize-then-rewrite-and-name-scoped-token-idor-ghsa.md)

- [**mcp-atlassian 20-GHSA confused-deputy cluster — five broken gates around one stored-credential MCP (Sept 22)**: the most-deployed Jira/Confluence MCP server: transport auth accepts **any non-empty token**, auth provider off by default, headerless requests fall back to `JiraConfig.from_env()` = **unauthenticated operator-credential access** (CVE-2026-77244); `ENABLED_TOOLS`/`TOOLSETS`/project filters enforced at **`tools/list` only** — direct `tools/call` hits the full 73-tool registry (77243/77251): **list-time enforcement is no enforcement** — sweep any disabled-tool config by calling the hidden names; `upload_attachment(file_path=…)` `open()`s **server-local files** and uploads them where the caller can read them = deterministic confused-deputy file-read oracle chained to unauth arbitrary file read (10 GHSAs, validator missing per-tool); prior traversal fix defaults `base_dir` to `os.getcwd()` (`/app`) → overwrite the app's own modules → RCE on restart — "patched" ≥0.17.0 silently vulnerable (77271); SSRF guard bypass ×4 legs (`urlparse` `\@` differential, redirect hook missing on basic-auth/OAuth branches, DNS rebinding, incomplete fix). **Any MCP/gateway holding server-side credentials inherits this five-gate checklist.** + seven same-wave folds: Nuclei template-sandbox 5-pack (DAST branch skips code signing, workflow loader skips `-file`, MySQL `allowAllFiles` = malicious-server-driven `LOAD DATA LOCAL INFILE` scanner file read, double-eval env leak, Goja engine native RCE) onto the Sept 16 Nuclei page; OpenBao trio (recovery-token timing leak, templated-policy `*` username glob escalation, LIST skips deny) onto May 28; Traefik singleflight concurrency-only enum oracle + Tinyauth case-mismatch ACL fail-open onto Sept 15; Unleash missing-`await` auth bypass + Gardener `User`-kind-only member gate + KubeEdge CRD-field shell injection onto Sept 21; IPv6-transition wrappers (`64:ff9b::v4`, `::v4`, `2002:`) defeat IPv4 SSRF classifiers (Cloudreve/LightRAG) onto July 7; Fabio Connection-header stripping of operator trust headers onto Aug 28; Home Assistant mDNS `_ipp._tcp` announcement = unauthenticated LAN SSRF onto Aug 5. KEV unchanged (2026.09.22, 1721); all blog feeds unchanged](alerts/2026-09-22-mcp-atlassian-server-side-credential-deputy-cluster-ghsa.md)

- [**Lantronix SLC8000/EMG serial-console appliance cluster — snprintf truncation as a redirect primitive (Sept 22)**: 13-GHSA wave on serial console servers (own one = console authority over every downstream switch/router/PDU). **CVE-2026-80155 (10.0)**: session-cookie file path built with fixed-buffer `snprintf` — a chosen-length cookie truncates the path at the delimiter, then traversal redirects the session-validation file read to an arbitrary on-disk file (the user DB) = unauthenticated read + upload → RCE; **CVE-2026-80154 (9.6)**: session tokens derived from **device model + one-second clock** = enumerable window + extension-handling bypass of per-session IP/UA binding; **CVE-2026-80148/80149/80150**: WebSSH overlong-username truncation drops the appended device-IP suffix → the appliance SSHes/Telnets to an attacker-chosen host (unauth SSRF); **4×9.9**: undocumented `mfc eeprom read/write` CLI verbs → bounded stack buffer + `system()` as root for *any* authenticated user. Durable axes: **fixed-buffer truncation is a redirect primitive** (path → file-selector hijack, host → connection-target hijack — for every field concatenated with a trusted suffix, ask what the final string actually is), **audit token derivation inputs not token length**, **enumerate undocumented CLI verbs from firmware strings**, and sanitizer **combination** tests (`..\/..`) on every filename check. + six same-evening folds: Virtualizor `from_billing_module` parameter-presence auth skip → unauth root RCE/POI/balance-UPDATE (43641–43643), Deepstream `PATCH_MULTI` unregistered-in-rules-map fail-open + MISP ACL-typo + Databasement validate-once invite tokens, MISP phar-wrapper-with-no-consumer, Kimi Code `.mcp.json` spawn-before-trust-prompt + plantable bare-name helpers, Tauri updater `allowDowngrades` from webview JS (XSS → anti-rollback off) + microsandbox secrets in world-readable argv, Concrete CMS order-timestamp download tokens. KEV moved to catalog 2026.09.22 (1721): F5 BIG-IP APM, Check Point Mgmt traversal + **Quantum gateway cert-validation VPN RCE (85102, 9.8, due 09-25)**, VeloCloud VCO](alerts/2026-09-22-lantronix-slc8000-emg-appliance-primitive-cluster-ghsa.md)
- [**F5 BIG-IP APM + OAuth profile unauthenticated data-plane RCE — composite-config perimeter validation (Sept 22)**: CVE-2026-94127 / GHSA-qppv-6jrg-hxq4 (9.8): unauthenticated RCE when a virtual server carries **both an APM access policy and an OAuth profile** — Appliance mode not a mitigation, data-plane only. Durable axes: version-only scans false-positive on **config-intersection surfaces** (enumerate vserver→profile bindings read-only and report the intersection count); the OAuth/APM federation endpoint is **pre-auth parser surface by design** — map what each licensed module adds to a shared listener, one module's profile widens another's attack surface; report severity from intersection + traffic behind the vserver, not the build string. + three same-wave folds: **9router `X-9r-Real-Ip`** header spoof = unauthenticated LLM API + rotating-header lockout-bucket reset (CVE-2026-56681/56682) onto the Aug 28 9router page — audit *vendor-branded* forwarding headers and whether the sanitizing wrapper is actually in the path; **SGLang diffusion `DiffusionServer` unauthenticated ZMQ ROUTER → `pickle.loads()` before validation** (CVE-2026-93088) + NeMo `.pkl`/`model_config.yaml` pack (65179/65178) onto the July 30 SGLang page — side-channel listeners are API surface once routable, config files are input surface; **MISP second wave** onto the Sept 21 page — `readFile && http || https` precedence-dead guard feeding unauth `cspReport` XML-locator SSRF (95679), `unlockedActions` CSRF-stripped module executor (95658), `tmp_name` probed before `is_uploaded_file()` file-oracle (95703), parent-checked/child-ACL-skipped enrichment + soft-deleted disclosure (95683), POST-only authz vs POST+PUT persistence (95671); **MarketKing IDOR quad** (payout-view, vendor-dump, product-copy, any-order-refund, 93341–93344) onto the Sept 19 WP page — multi-vendor plugins are tenancy WP never checks, and the duplicate primitive is copy-exfil](alerts/2026-09-22-f5-bigip-apm-access-policy-oauth-profile-unauth-rce-validation-boundary-ghsa.md)

- [**Payment-credential challenge-binding — ZenHive mpp micropayment rail (Sept 22)**: two GHSAs, one primitive, opposite victims: voucher whose `cumulativeAmount` **equals the already-accepted amount** treated as idempotent success → resource served, spend never runs, replay store keys on the per-request challenge so one voucher buys **unbounded units** (CVE-2026-89420); Tempo key authorization signs chain/key/expiry/limits/scopes but **not the challenge**, activation dedup keys on challenge id → captured credential **re-charges the payer's wallet** every replay (CVE-2026-87119). Rule for any paid MCP/agent endpoint, x402-style header, or metered API: **the dedup key and the signature payload must overlap — sweep which copy of session state the verifier reads vs which the dedup/effect layer reads**, and run the fresh-challenge replay + ledger-delta battery per transport. + folds: Tauri HTTP plugin scope checked once, redirects followed unscoped (CVE-2026-95623); Open VSX CDN-layer CORS reflection + readable `/user/csrf` → publish-token theft (CVE-2026-90882); Checkmk GUI-masked SNMP/IPMI secrets served by REST to viewers (CVE-2026-92882) + Livestatus newline count-oracle (CVE-2026-90990)](alerts/2026-09-22-micro-payment-credential-challenge-binding-and-amount-equality-idempotency-ghsa.md)

- [**WordPress render-vs-process authz parity + options-import ladder (Sept 22 fold)**: Meta Box AIO ≤3.11.0 unauth→Administrator chain (CVE-2026-13355): form target `object_id` overridden from GET with no authz + `Form::process()` lacks the `user_can_edit()` check its `render()` has → unauth arbitrary-page content write with an injected shortcode → user-profile component trusts the shortcode's `role`/`auto_login` attributes → register-as-admin. Rule: **render-path capability checks must be re-proven on the process endpoint** — call submit without ever rendering; treat any `*_object_id` parameter as a target-selection pivot; injected WP content is parsed as trusted configuration (privilege-bearing shortcode attributes). CMP ≤4.1.17 editor→admin via nonce-only `cmp_ajax_import_settings` arbitrary-option write (`default_role`=admin + open registration). Give Tributes ≤2.3.1 unauth POI reachable only under one config posture (Multiple-Recipients ON + custom-message OFF) — **configuration posture is part of the exploitability proof**, sweep every toggle that switches which sibling path runs your input. Folded onto the Sept 19 WP alternate-surface page](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md#september-22-follow-up-render-vs-process-authz-parity-options-import-ladders-and-config-posture-gated-poi-6-ghsas)

- [**Tauri desktop IPC, CSP, and scope-escalation cluster — the webview is the supply chain (Sept 23)**: three GHSAs show each Tauri defense enforces less than its name: **CSP nonce hardening is zero protection when `script-src` lists `data:`/`blob:`** (scheme sources stay active with a nonce per CSP L3 — any renderer XSS = arbitrary exec without ever learning the nonce, CVE-2026-95626); dialog-plugin **recursive scope escalation — one ordinary file-picker click grants silent, permanent, unrevocable read/write over an entire directory tree** (95627); **Pake-generated apps ship `remote.urls: https://*.*` + `withGlobalTauri`, and Tauri's ACL never checks app (`generate_handler!`) commands** → any HTTPS origin in the window (including the wrapped site's own ad/analytics scripts) invokes every native command, chained to `download_file` path traversal (96454). Rule: audit the *enforced property*, not the gate's name. + four folds: Tomcat second train (WebSocket alternate-name constraint bypass 76183, HTTP/2 smuggling **as a regression in the CVE-2026-41293 fix** 86350, cross-stream trailer bleed 77762, Jakarta realm first-wins 75973, keystore CRL-skip 73581) onto the Aug 26 Tomcat page; Keycloak **PAR `request_uri` single-use check skipped on the `prompt=none` silent path** (96446) + Conditional OTP header-trusted 2FA skip (96445) onto the June 11 identity page; ManageEngine OpManager **Configlet SSTI → fleet-credential appliance RCE** + Report Profile import → admin (12370/84787) onto the Sept 21 mgmt-plane page; Reachy Mini **unauth `POST /apps/install` = attacker-chosen Hugging Face Space → pip build-code RCE, CORS-only vendor fix (CORS fixes ≠ authn fixes)** + Bluetooth shared-auth flag ignoring calling-device identity (96455/96456) onto the June 23 appliance page. Tracked: Emacs Flymake edit-time exec, Doris JDBC-URL FE RCE, Sling filter-shape pair. KEV unchanged (2026.09.22, 1721)](alerts/2026-09-23-tauri-desktop-ipc-csp-scope-and-webview-supply-chain-ghsa.md)




## What lives here



































































## What lives here

- **Skills**: installable, tool-specific guides that agents can execute step by step
- **Recon**: workflows for turning scope into a prioritized asset map
- **Exploit Paths**: concrete attack chains that are specific enough to replay during authorized testing
- **Templates**: reusable report skeletons and delivery formats
- **Notes**: editorial guidance, taxonomy, and source tracking
- **Blog**: short updates when major skills or exploit paths land

Older alert and mitigation-oriented reference pages may remain in the repo, but the primary site surface is intentionally centered on pentesting, red-team, and bug-bounty operator workflows.

## How the skills are written

Each skill page is structured so it can be reused outside the wiki:

- When to use the tool
- Required inputs and prerequisites
- Command patterns worth reusing
- Expected outputs and what to capture
- Safety constraints and scope boundaries

!!! warning "Authorized use only"
    These pages are for lawful research, lab work, and authorized assessments. Do not apply them to systems you do not own or lack explicit permission to test.
