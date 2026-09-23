---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**Payment-gateway webhook branch integrity + client-trusted amount state — five-plugin WP/WC cluster (Sept 23)**: Premium Packages **never verifies PayPal webhook signatures** → unauth forged payment confirmations/cancellations for any known transaction id (CVE-2026-93511); Paymob verifies signatures on the payment branch but **not the card-token branch** → unauth card-token write on any account + account enumeration (87979), plus contributor-reachable gateway-config wipe (87981); Payment Plugins' order-ownership check **runs only when the PayPal order is already completed** → replay a victim's *approved-uncaptured* order id on your own checkout and the victim's funds are captured against your order (80342) — every `if (state == X) verify()` hides an unverified non-X path; Better Payment never re-derives amount server-side (77765); Points and Rewards claim handler validates neither amount nor caller → Subscriber self-credits unlimited points (93510). Axes: webhook signature coverage is **per-branch**, test every event-type leg with forged payloads; probe the **skip-condition** of conditional integrity checks across the state machine; amounts/rewards are server-derived or attacker-derived; opaque ids become credentials when verification is absent (report id structure/enumerability). + folds: WP OAuth Server **returns the most-recently-authenticated user's OIDC assertion** for any grant → Subscriber mint admin-signed identity for the whole SSO fleet (82843, two-account interleaved grant battery); Directorist wave = **fix-history recon** (incomplete fix of CVE-2023-1889 via unpatched deletion path + 8.9.1 regression of a correctly-fixed 8.8.1 endpoint — re-run old CVEs, bisect ranges); Easy Hide Login leaks the secret slug via always-public reset flow (satellite-route fuzzing); YAHMAN remote-file cache = unauth PHP write→RCE (fetch-then-store *write leg* is the sink); Forminator anonymous mail-send carries site template + attacker link, plugin-minted replayable token; WC Fields Factory subscriber arbitrary post-meta write incl. product pricing rules. LMDeploy `load_image()` VL SSRF with 0.0.0.0 bind + auth-off defaults onto the SGLang page](alerts/2026-09-23-woocommerce-payment-webhook-branch-and-amount-integrity-cluster-ghsa.md)

- [**GHES appliance surface: port-blind SSRF with timing oracle → RCE, sanitize-then-rewrite XSS, name-scoped diff-token IDOR (Sept 22)**: notebook viewer validated URL **scheme+host but not port** → same-appliance internal services reachable with a guard-passing URL; **no response body but response timing leaked instance secrets character-by-character**, then the secret chained into an internal-service interaction = **unauthenticated appliance RCE** (CVE-2026-77987, critical; private-mode posture decides auth requirement) — durable axes: **port is a first-class SSRF validation dimension and approved-host-plus-foreign-port is the tuple guards miss**, and **latency is an extraction oracle when bodies are withheld** (generalizes the Sept 17 outer-status oracle). Markdown pipeline **rewrote quotes in already-sanitized HTML and rendered the rewritten copy unsanitized** → attribute injection, same-origin JS gadgets defeat CSP, payload propagates through the victim’s write access (CVE-2026-77912) — post-sanitizer transformations invalidate the sanitizer verdict; fuzz canaries that only activate after rewriting. Raw-diff tokens scoped to **repo name + PR number instead of unique id** → create a colliding repo/PR, replay your own token against the private target (CVE-2026-75101) — **name-unique scope keys = collision IDOR generator**. + two same-wave folds: **Skipper OPA body-authz third variant** (CVE-2026-86043) onto the July 8 page — the recommended `truncated_body == false` guard itself fails open on chunked/H2 because the flag is only computed when content-length exists: test vendor mitigations with the flag **absent vs false vs true**; **Vaultwarden revoked/pending members keep org-cipher access** (CVE-2026-95814) onto the Sept 21 auth-precedence page — membership-status enum missing from access-query predicates. Tracked detail-free: SolarWinds Observability Self-Hosted unauth RCE pair (28324/28325), Rockwell ALE ~10-GHSA cluster incl. default creds + unauth elevated file write, Unbound DNSKEY self-compression-pointer digest overflow (81642), Emacs read-symbol-shorthands RCE, OpenClaw iOS logged bearer keys, Mattermost OAuth-leg internal SSRF. KEV unchanged (catalog 2026.09.22, 1721); all blog feeds unchanged](alerts/2026-09-22-ghes-appliance-surface-port-blind-ssrf-timing-oracle-sanitize-then-rewrite-and-name-scoped-token-idor-ghsa.md)

- [**mcp-atlassian 20-GHSA confused-deputy cluster — five broken gates around one stored-credential MCP (Sept 22)**: the most-deployed Jira/Confluence MCP server: transport auth accepts **any non-empty token**, auth provider off by default, headerless requests fall back to `JiraConfig.from_env()` = **unauthenticated operator-credential access** (CVE-2026-77244); `ENABLED_TOOLS`/`TOOLSETS`/project filters enforced at **`tools/list` only** — direct `tools/call` hits the full 73-tool registry (77243/77251): **list-time enforcement is no enforcement** — sweep any disabled-tool config by calling the hidden names; `upload_attachment(file_path=…)` `open()`s **server-local files** and uploads them where the caller can read them = deterministic confused-deputy file-read oracle chained to unauth arbitrary file read (10 GHSAs, validator missing per-tool); prior traversal fix defaults `base_dir` to `os.getcwd()` (`/app`) → overwrite the app's own modules → RCE on restart — "patched" ≥0.17.0 silently vulnerable (77271); SSRF guard bypass ×4 legs (`urlparse` `\@` differential, redirect hook missing on basic-auth/OAuth branches, DNS rebinding, incomplete fix). **Any MCP/gateway holding server-side credentials inherits this five-gate checklist.** + seven same-wave folds: Nuclei template-sandbox 5-pack (DAST branch skips code signing, workflow loader skips `-file`, MySQL `allowAllFiles` = malicious-server-driven `LOAD DATA LOCAL INFILE` scanner file read, double-eval env leak, Goja engine native RCE) onto the Sept 16 Nuclei page; OpenBao trio (recovery-token timing leak, templated-policy `*` username glob escalation, LIST skips deny) onto May 28; Traefik singleflight concurrency-only enum oracle + Tinyauth case-mismatch ACL fail-open onto Sept 15; Unleash missing-`await` auth bypass + Gardener `User`-kind-only member gate + KubeEdge CRD-field shell injection onto Sept 21; IPv6-transition wrappers (`64:ff9b::v4`, `::v4`, `2002:`) defeat IPv4 SSRF classifiers (Cloudreve/LightRAG) onto July 7; Fabio Connection-header stripping of operator trust headers onto Aug 28; Home Assistant mDNS `_ipp._tcp` announcement = unauthenticated LAN SSRF onto Aug 5. KEV unchanged (2026.09.22, 1721); all blog feeds unchanged](alerts/2026-09-22-mcp-atlassian-server-side-credential-deputy-cluster-ghsa.md)

- [**Lantronix SLC8000/EMG serial-console appliance cluster — snprintf truncation as a redirect primitive (Sept 22)**: 13-GHSA wave on serial console servers (own one = console authority over every downstream switch/router/PDU). **CVE-2026-80155 (10.0)**: session-cookie file path built with fixed-buffer `snprintf` — a chosen-length cookie truncates the path at the delimiter, then traversal redirects the session-validation file read to an arbitrary on-disk file (the user DB) = unauthenticated read + upload → RCE; **CVE-2026-80154 (9.6)**: session tokens derived from **device model + one-second clock** = enumerable window + extension-handling bypass of per-session IP/UA binding; **CVE-2026-80148/80149/80150**: WebSSH overlong-username truncation drops the appended device-IP suffix → the appliance SSHes/Telnets to an attacker-chosen host (unauth SSRF); **4×9.9**: undocumented `mfc eeprom read/write` CLI verbs → bounded stack buffer + `system()` as root for *any* authenticated user. Durable axes: **fixed-buffer truncation is a redirect primitive** (path → file-selector hijack, host → connection-target hijack — for every field concatenated with a trusted suffix, ask what the final string actually is), **audit token derivation inputs not token length**, **enumerate undocumented CLI verbs from firmware strings**, and sanitizer **combination** tests (`..\/..`) on every filename check. + six same-evening folds: Virtualizor `from_billing_module` parameter-presence auth skip → unauth root RCE/POI/balance-UPDATE (43641–43643), Deepstream `PATCH_MULTI` unregistered-in-rules-map fail-open + MISP ACL-typo + Databasement validate-once invite tokens, MISP phar-wrapper-with-no-consumer, Kimi Code `.mcp.json` spawn-before-trust-prompt + plantable bare-name helpers, Tauri updater `allowDowngrades` from webview JS (XSS → anti-rollback off) + microsandbox secrets in world-readable argv, Concrete CMS order-timestamp download tokens. KEV moved to catalog 2026.09.22 (1721): F5 BIG-IP APM, Check Point Mgmt traversal + **Quantum gateway cert-validation VPN RCE (85102, 9.8, due 09-25)**, VeloCloud VCO](alerts/2026-09-22-lantronix-slc8000-emg-appliance-primitive-cluster-ghsa.md)
- [**F5 BIG-IP APM + OAuth profile unauthenticated data-plane RCE — composite-config perimeter validation (Sept 22)**: CVE-2026-94127 / GHSA-qppv-6jrg-hxq4 (9.8): unauthenticated RCE when a virtual server carries **both an APM access policy and an OAuth profile** — Appliance mode not a mitigation, data-plane only. Durable axes: version-only scans false-positive on **config-intersection surfaces** (enumerate vserver→profile bindings read-only and report the intersection count); the OAuth/APM federation endpoint is **pre-auth parser surface by design** — map what each licensed module adds to a shared listener, one module's profile widens another's attack surface; report severity from intersection + traffic behind the vserver, not the build string. + three same-wave folds: **9router `X-9r-Real-Ip`** header spoof = unauthenticated LLM API + rotating-header lockout-bucket reset (CVE-2026-56681/56682) onto the Aug 28 9router page — audit *vendor-branded* forwarding headers and whether the sanitizing wrapper is actually in the path; **SGLang diffusion `DiffusionServer` unauthenticated ZMQ ROUTER → `pickle.loads()` before validation** (CVE-2026-93088) + NeMo `.pkl`/`model_config.yaml` pack (65179/65178) onto the July 30 SGLang page — side-channel listeners are API surface once routable, config files are input surface; **MISP second wave** onto the Sept 21 page — `readFile && http || https` precedence-dead guard feeding unauth `cspReport` XML-locator SSRF (95679), `unlockedActions` CSRF-stripped module executor (95658), `tmp_name` probed before `is_uploaded_file()` file-oracle (95703), parent-checked/child-ACL-skipped enrichment + soft-deleted disclosure (95683), POST-only authz vs POST+PUT persistence (95671); **MarketKing IDOR quad** (payout-view, vendor-dump, product-copy, any-order-refund, 93341–93344) onto the Sept 19 WP page — multi-vendor plugins are tenancy WP never checks, and the duplicate primitive is copy-exfil](alerts/2026-09-22-f5-bigip-apm-access-policy-oauth-profile-unauth-rce-validation-boundary-ghsa.md)

- [**Payment-credential challenge-binding — ZenHive mpp micropayment rail (Sept 22)**: two GHSAs, one primitive, opposite victims: voucher whose `cumulativeAmount` **equals the already-accepted amount** treated as idempotent success → resource served, spend never runs, replay store keys on the per-request challenge so one voucher buys **unbounded units** (CVE-2026-89420); Tempo key authorization signs chain/key/expiry/limits/scopes but **not the challenge**, activation dedup keys on challenge id → captured credential **re-charges the payer's wallet** every replay (CVE-2026-87119). Rule for any paid MCP/agent endpoint, x402-style header, or metered API: **the dedup key and the signature payload must overlap — sweep which copy of session state the verifier reads vs which the dedup/effect layer reads**, and run the fresh-challenge replay + ledger-delta battery per transport. + folds: Tauri HTTP plugin scope checked once, redirects followed unscoped (CVE-2026-95623); Open VSX CDN-layer CORS reflection + readable `/user/csrf` → publish-token theft (CVE-2026-90882); Checkmk GUI-masked SNMP/IPMI secrets served by REST to viewers (CVE-2026-92882) + Livestatus newline count-oracle (CVE-2026-90990)](alerts/2026-09-22-micro-payment-credential-challenge-binding-and-amount-equality-idempotency-ghsa.md)

- [**WordPress render-vs-process authz parity + options-import ladder (Sept 22 fold)**: Meta Box AIO ≤3.11.0 unauth→Administrator chain (CVE-2026-13355): form target `object_id` overridden from GET with no authz + `Form::process()` lacks the `user_can_edit()` check its `render()` has → unauth arbitrary-page content write with an injected shortcode → user-profile component trusts the shortcode's `role`/`auto_login` attributes → register-as-admin. Rule: **render-path capability checks must be re-proven on the process endpoint** — call submit without ever rendering; treat any `*_object_id` parameter as a target-selection pivot; injected WP content is parsed as trusted configuration (privilege-bearing shortcode attributes). CMP ≤4.1.17 editor→admin via nonce-only `cmp_ajax_import_settings` arbitrary-option write (`default_role`=admin + open registration). Give Tributes ≤2.3.1 unauth POI reachable only under one config posture (Multiple-Recipients ON + custom-message OFF) — **configuration posture is part of the exploitability proof**, sweep every toggle that switches which sibling path runs your input. Folded onto the Sept 19 WP alternate-surface page](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md#september-22-follow-up-render-vs-process-authz-parity-options-import-ladders-and-config-posture-gated-poi-6-ghsas)

- [**Guard verdict vs sink copy — Dancer2 four-GHSA cluster (Sept 22)**: Dancer2 <2.2.0: `headers_to_array` strips CR/LF from header **values but not names** → a request-derived header name carrying CRLF = response splitting (CVE-2026-93711); a dying `before` hook's refusal **still runs the route body and its writes** when the exception handler halts via the keyword instead of the response object — the caller sees a refusal the server never enforced (CVE-2026-93710): on every hook/middleware-enforced gate, build a response-status-vs-side-effect fidelity table; AutoPage guard compares the path **as text** while the lookup canonicalizes → `//`, dot segments, `%2f`, case variants escape it (CVE-2026-93709); File handler joins **uncollapsed `..`** onto `public_dir`, checks only "readable regular file" → unauth `config.yml` read, but only once `static_handler: 0` — **config posture is the precondition probe** (CVE-2026-93712). + fold: Python stdlib `tarfile` **ignores the data-filter's `None` deny verdict on the link-unsupported fallback branch** (CVE-2026-87910) onto the May 6 extraction page — fallback branches are where filter verdicts get dropped](alerts/2026-09-22-dancer2-guard-semantics-header-name-crlf-hook-refusal-dispatch-and-path-spelling-differentials-ghsa.md)

- [**AD CS plaintext CA fetch → trust-store poisoning (Sept 21 fold, CVE-2026-12249)**: Canonical ADSys ≤0.16.2 auto-enrolls AD CS certificates via a vendored Samba GPO script that fetches the CA cert with `GetCACert` over **plaintext `http://`** — an **unauthenticated on-path attacker** returns an arbitrary root CA, which ADSys installs into the **OS trust store** via `update-ca-certificates` → every TLS client on the host accepts rogue certs for any domain, persistently. Axes: grep enrollment/GPO agent source for `http://` + CA-fetch/trust-update calls (trust material over unauthenticated channels = anchor injection), the CA hostname arrives via GPO so a DNS answer controls the leg, and the injected root survives reboots = persistence; fingerprint fleet versions, prove only with lab-generated fake roots + owned canaries. Folded onto the July 27 directory-boundaries page alongside the SSSD sudo/GPO cluster](alerts/2026-07-27-directory-cluster-agent-document-boundaries-ghsa.md#september-21-follow-up-adsys-ad-cs-ca-fetch-over-plaintext-http-poisons-the-system-trust-store)

- [**Management-plane config-write ladders + TOCTOU onboarding race + flat authz drift (Sept 21)**: nginx-ignition `/api/users/onboarding/finish` is **anonymous, all-ReadWrite, and TOCTOU-raced** → unauthenticated admin creation, multiple admins per concurrent burst (CVE-2026-61628) — sweep `/setup/*` `/init/*` route families and race them. **OpenStack Octavia critical pair**: an RFC-3986 validator **percent-encodes control chars before validating while storage keeps raw** → newline-injected HAProxy directives via L7 `redirect_url` (CVE-2026-94571), and `tls_ciphers` writes verbatim to the same generated config (CVE-2026-94572) — enumerate every field rendered into config files. **ZLMediaKit unauth `setServerConfig`** writes shell text into `ffmpeg.snap`, executed later by `getSnap` (CVE-2026-67827): config-set APIs are RCE with a delay. **x-ui**: signed cookie carries the full user object with **no DB revalidation** → rotated passwords don't revoke old admin sessions (CVE-2026-79317); low-role template edit + restart **rebinds the management gRPC off loopback** (CVE-2026-79316). **jshERP nine-GHSA ladder**: `type=UserRole` generic updater = **self-grant tenant admin in one POST** (94411), `resetPwd` any user (94412), `/user/info` leaks **unsalted MD5 hashes** (94413), key-iteration cross-tenant enum (94494). + fold: `pquerna/otp` **ships no consumed-TOTP tracking by design** → one captured code is a ~30 s reuse lane (CVE-2026-61630) onto the Sept 18 token page](alerts/2026-09-21-management-plane-config-writes-toctou-onboarding-race-and-flat-authz-drift-ghsa.md)



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
