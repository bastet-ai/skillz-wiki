---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**mcp-atlassian 20-GHSA confused-deputy cluster — five broken gates around one stored-credential MCP (Sept 22)**: the most-deployed Jira/Confluence MCP server: transport auth accepts **any non-empty token**, auth provider off by default, headerless requests fall back to `JiraConfig.from_env()` = **unauthenticated operator-credential access** (CVE-2026-77244); `ENABLED_TOOLS`/`TOOLSETS`/project filters enforced at **`tools/list` only** — direct `tools/call` hits the full 73-tool registry (77243/77251): **list-time enforcement is no enforcement** — sweep any disabled-tool config by calling the hidden names; `upload_attachment(file_path=…)` `open()`s **server-local files** and uploads them where the caller can read them = deterministic confused-deputy file-read oracle chained to unauth arbitrary file read (10 GHSAs, validator missing per-tool); prior traversal fix defaults `base_dir` to `os.getcwd()` (`/app`) → overwrite the app's own modules → RCE on restart — "patched" ≥0.17.0 silently vulnerable (77271); SSRF guard bypass ×4 legs (`urlparse` `\@` differential, redirect hook missing on basic-auth/OAuth branches, DNS rebinding, incomplete fix). **Any MCP/gateway holding server-side credentials inherits this five-gate checklist.** + seven same-wave folds: Nuclei template-sandbox 5-pack (DAST branch skips code signing, workflow loader skips `-file`, MySQL `allowAllFiles` = malicious-server-driven `LOAD DATA LOCAL INFILE` scanner file read, double-eval env leak, Goja engine native RCE) onto the Sept 16 Nuclei page; OpenBao trio (recovery-token timing leak, templated-policy `*` username glob escalation, LIST skips deny) onto May 28; Traefik singleflight concurrency-only enum oracle + Tinyauth case-mismatch ACL fail-open onto Sept 15; Unleash missing-`await` auth bypass + Gardener `User`-kind-only member gate + KubeEdge CRD-field shell injection onto Sept 21; IPv6-transition wrappers (`64:ff9b::v4`, `::v4`, `2002:`) defeat IPv4 SSRF classifiers (Cloudreve/LightRAG) onto July 7; Fabio Connection-header stripping of operator trust headers onto Aug 28; Home Assistant mDNS `_ipp._tcp` announcement = unauthenticated LAN SSRF onto Aug 5. KEV unchanged (2026.09.22, 1721); all blog feeds unchanged](alerts/2026-09-22-mcp-atlassian-server-side-credential-deputy-cluster-ghsa.md)

- [**Lantronix SLC8000/EMG serial-console appliance cluster — snprintf truncation as a redirect primitive (Sept 22)**: 13-GHSA wave on serial console servers (own one = console authority over every downstream switch/router/PDU). **CVE-2026-80155 (10.0)**: session-cookie file path built with fixed-buffer `snprintf` — a chosen-length cookie truncates the path at the delimiter, then traversal redirects the session-validation file read to an arbitrary on-disk file (the user DB) = unauthenticated read + upload → RCE; **CVE-2026-80154 (9.6)**: session tokens derived from **device model + one-second clock** = enumerable window + extension-handling bypass of per-session IP/UA binding; **CVE-2026-80148/80149/80150**: WebSSH overlong-username truncation drops the appended device-IP suffix → the appliance SSHes/Telnets to an attacker-chosen host (unauth SSRF); **4×9.9**: undocumented `mfc eeprom read/write` CLI verbs → bounded stack buffer + `system()` as root for *any* authenticated user. Durable axes: **fixed-buffer truncation is a redirect primitive** (path → file-selector hijack, host → connection-target hijack — for every field concatenated with a trusted suffix, ask what the final string actually is), **audit token derivation inputs not token length**, **enumerate undocumented CLI verbs from firmware strings**, and sanitizer **combination** tests (`..\/..`) on every filename check. + six same-evening folds: Virtualizor `from_billing_module` parameter-presence auth skip → unauth root RCE/POI/balance-UPDATE (43641–43643), Deepstream `PATCH_MULTI` unregistered-in-rules-map fail-open + MISP ACL-typo + Databasement validate-once invite tokens, MISP phar-wrapper-with-no-consumer, Kimi Code `.mcp.json` spawn-before-trust-prompt + plantable bare-name helpers, Tauri updater `allowDowngrades` from webview JS (XSS → anti-rollback off) + microsandbox secrets in world-readable argv, Concrete CMS order-timestamp download tokens. KEV moved to catalog 2026.09.22 (1721): F5 BIG-IP APM, Check Point Mgmt traversal + **Quantum gateway cert-validation VPN RCE (85102, 9.8, due 09-25)**, VeloCloud VCO](alerts/2026-09-22-lantronix-slc8000-emg-appliance-primitive-cluster-ghsa.md)
- [**F5 BIG-IP APM + OAuth profile unauthenticated data-plane RCE — composite-config perimeter validation (Sept 22)**: CVE-2026-94127 / GHSA-qppv-6jrg-hxq4 (9.8): unauthenticated RCE when a virtual server carries **both an APM access policy and an OAuth profile** — Appliance mode not a mitigation, data-plane only. Durable axes: version-only scans false-positive on **config-intersection surfaces** (enumerate vserver→profile bindings read-only and report the intersection count); the OAuth/APM federation endpoint is **pre-auth parser surface by design** — map what each licensed module adds to a shared listener, one module's profile widens another's attack surface; report severity from intersection + traffic behind the vserver, not the build string. + three same-wave folds: **9router `X-9r-Real-Ip`** header spoof = unauthenticated LLM API + rotating-header lockout-bucket reset (CVE-2026-56681/56682) onto the Aug 28 9router page — audit *vendor-branded* forwarding headers and whether the sanitizing wrapper is actually in the path; **SGLang diffusion `DiffusionServer` unauthenticated ZMQ ROUTER → `pickle.loads()` before validation** (CVE-2026-93088) + NeMo `.pkl`/`model_config.yaml` pack (65179/65178) onto the July 30 SGLang page — side-channel listeners are API surface once routable, config files are input surface; **MISP second wave** onto the Sept 21 page — `readFile && http || https` precedence-dead guard feeding unauth `cspReport` XML-locator SSRF (95679), `unlockedActions` CSRF-stripped module executor (95658), `tmp_name` probed before `is_uploaded_file()` file-oracle (95703), parent-checked/child-ACL-skipped enrichment + soft-deleted disclosure (95683), POST-only authz vs POST+PUT persistence (95671); **MarketKing IDOR quad** (payout-view, vendor-dump, product-copy, any-order-refund, 93341–93344) onto the Sept 19 WP page — multi-vendor plugins are tenancy WP never checks, and the duplicate primitive is copy-exfil](alerts/2026-09-22-f5-bigip-apm-access-policy-oauth-profile-unauth-rce-validation-boundary-ghsa.md)

- [**Payment-credential challenge-binding — ZenHive mpp micropayment rail (Sept 22)**: two GHSAs, one primitive, opposite victims: voucher whose `cumulativeAmount` **equals the already-accepted amount** treated as idempotent success → resource served, spend never runs, replay store keys on the per-request challenge so one voucher buys **unbounded units** (CVE-2026-89420); Tempo key authorization signs chain/key/expiry/limits/scopes but **not the challenge**, activation dedup keys on challenge id → captured credential **re-charges the payer's wallet** every replay (CVE-2026-87119). Rule for any paid MCP/agent endpoint, x402-style header, or metered API: **the dedup key and the signature payload must overlap — sweep which copy of session state the verifier reads vs which the dedup/effect layer reads**, and run the fresh-challenge replay + ledger-delta battery per transport. + folds: Tauri HTTP plugin scope checked once, redirects followed unscoped (CVE-2026-95623); Open VSX CDN-layer CORS reflection + readable `/user/csrf` → publish-token theft (CVE-2026-90882); Checkmk GUI-masked SNMP/IPMI secrets served by REST to viewers (CVE-2026-92882) + Livestatus newline count-oracle (CVE-2026-90990)](alerts/2026-09-22-micro-payment-credential-challenge-binding-and-amount-equality-idempotency-ghsa.md)

- [**WordPress render-vs-process authz parity + options-import ladder (Sept 22 fold)**: Meta Box AIO ≤3.11.0 unauth→Administrator chain (CVE-2026-13355): form target `object_id` overridden from GET with no authz + `Form::process()` lacks the `user_can_edit()` check its `render()` has → unauth arbitrary-page content write with an injected shortcode → user-profile component trusts the shortcode's `role`/`auto_login` attributes → register-as-admin. Rule: **render-path capability checks must be re-proven on the process endpoint** — call submit without ever rendering; treat any `*_object_id` parameter as a target-selection pivot; injected WP content is parsed as trusted configuration (privilege-bearing shortcode attributes). CMP ≤4.1.17 editor→admin via nonce-only `cmp_ajax_import_settings` arbitrary-option write (`default_role`=admin + open registration). Give Tributes ≤2.3.1 unauth POI reachable only under one config posture (Multiple-Recipients ON + custom-message OFF) — **configuration posture is part of the exploitability proof**, sweep every toggle that switches which sibling path runs your input. Folded onto the Sept 19 WP alternate-surface page](alerts/2026-09-19-wordpress-alternate-surface-authz-drift-rest-ajax-import-wave-ghsa.md#september-22-follow-up-render-vs-process-authz-parity-options-import-ladders-and-config-posture-gated-poi-6-ghsas)

- [**Guard verdict vs sink copy — Dancer2 four-GHSA cluster (Sept 22)**: Dancer2 <2.2.0: `headers_to_array` strips CR/LF from header **values but not names** → a request-derived header name carrying CRLF = response splitting (CVE-2026-93711); a dying `before` hook's refusal **still runs the route body and its writes** when the exception handler halts via the keyword instead of the response object — the caller sees a refusal the server never enforced (CVE-2026-93710): on every hook/middleware-enforced gate, build a response-status-vs-side-effect fidelity table; AutoPage guard compares the path **as text** while the lookup canonicalizes → `//`, dot segments, `%2f`, case variants escape it (CVE-2026-93709); File handler joins **uncollapsed `..`** onto `public_dir`, checks only "readable regular file" → unauth `config.yml` read, but only once `static_handler: 0` — **config posture is the precondition probe** (CVE-2026-93712). + fold: Python stdlib `tarfile` **ignores the data-filter's `None` deny verdict on the link-unsupported fallback branch** (CVE-2026-87910) onto the May 6 extraction page — fallback branches are where filter verdicts get dropped](alerts/2026-09-22-dancer2-guard-semantics-header-name-crlf-hook-refusal-dispatch-and-path-spelling-differentials-ghsa.md)

- [**AD CS plaintext CA fetch → trust-store poisoning (Sept 21 fold, CVE-2026-12249)**: Canonical ADSys ≤0.16.2 auto-enrolls AD CS certificates via a vendored Samba GPO script that fetches the CA cert with `GetCACert` over **plaintext `http://`** — an **unauthenticated on-path attacker** returns an arbitrary root CA, which ADSys installs into the **OS trust store** via `update-ca-certificates` → every TLS client on the host accepts rogue certs for any domain, persistently. Axes: grep enrollment/GPO agent source for `http://` + CA-fetch/trust-update calls (trust material over unauthenticated channels = anchor injection), the CA hostname arrives via GPO so a DNS answer controls the leg, and the injected root survives reboots = persistence; fingerprint fleet versions, prove only with lab-generated fake roots + owned canaries. Folded onto the July 27 directory-boundaries page alongside the SSSD sudo/GPO cluster](alerts/2026-07-27-directory-cluster-agent-document-boundaries-ghsa.md#september-21-follow-up-adsys-ad-cs-ca-fetch-over-plaintext-http-poisons-the-system-trust-store)

- [**Management-plane config-write ladders + TOCTOU onboarding race + flat authz drift (Sept 21)**: nginx-ignition `/api/users/onboarding/finish` is **anonymous, all-ReadWrite, and TOCTOU-raced** → unauthenticated admin creation, multiple admins per concurrent burst (CVE-2026-61628) — sweep `/setup/*` `/init/*` route families and race them. **OpenStack Octavia critical pair**: an RFC-3986 validator **percent-encodes control chars before validating while storage keeps raw** → newline-injected HAProxy directives via L7 `redirect_url` (CVE-2026-94571), and `tls_ciphers` writes verbatim to the same generated config (CVE-2026-94572) — enumerate every field rendered into config files. **ZLMediaKit unauth `setServerConfig`** writes shell text into `ffmpeg.snap`, executed later by `getSnap` (CVE-2026-67827): config-set APIs are RCE with a delay. **x-ui**: signed cookie carries the full user object with **no DB revalidation** → rotated passwords don't revoke old admin sessions (CVE-2026-79317); low-role template edit + restart **rebinds the management gRPC off loopback** (CVE-2026-79316). **jshERP nine-GHSA ladder**: `type=UserRole` generic updater = **self-grant tenant admin in one POST** (94411), `resetPwd` any user (94412), `/user/info` leaks **unsalted MD5 hashes** (94413), key-iteration cross-tenant enum (94494). + fold: `pquerna/otp` **ships no consumed-TOTP tracking by design** → one captured code is a ~30 s reuse lane (CVE-2026-61630) onto the Sept 18 token page](alerts/2026-09-21-management-plane-config-writes-toctou-onboarding-race-and-flat-authz-drift-ghsa.md)

- [**Legacy-CMS internal-namespace injection + URL-ingest SSRF + media-panel RCE ladder (Sept 21)**: CuteNews `cn_parse_url()` **deserializes base64 `__post_data` and merges it into `__`-prefixed internal request variables** — caller keys collide with app state; injected `__referer` renders as a `javascript:` link on `msg_info`, closing the blind-state-write → session-XSS loop (CVE-2026-36471/36472); Media Manager **Upload-by-URL = standalone SSRF leg** validators never cover (CVE-2026-36469); media-panel unrestricted upload = login-to-RCE (CVE-2026-36467); fuzz parameter **names** and **Referer-on-POST** for reflection (CVE-2026-36468/36470). Rule: sweep name-blind internal-namespace merges (`extract()`, `parse_str` no-target, `__`-prefix states), prove injection→read-sink chains, and URL-ingest features are SSRF even when input validators pass. + folds: Concrete CMS 8-GHSA cluster (**DNS-pin reused cross-port → rebinding import SSRF with saved-file response oracle**; anonymous-minted selector token + empty query = full account enumeration; CSRF token bound to user+action not object; source-side-only authz on relationship writes), Jenkins Script Security `@Builder` **class-name annotation member the whitelist never parses** → Pipeline sandbox escape (CVE-2026-92126, 8.5), Netty **semicolon-gated chunk validator lets `0\rX` through** + split-TE + trailing-control-byte RTSP method trim defeating the patched HTTP sibling (CVE-2026-93566/93565), Quarkus **security-matcher vs dispatcher normalization split** (CVE-2026-87743)](alerts/2026-09-21-cutenews-internal-namespace-injection-url-upload-ssrf-and-media-rce-ladder-ghsa.md)

- [**Auth-method precedence + verb-allowlist bypass + ACL tie-break drift (Sept 21)**: Airflow request with **cookie AND bearer** executes + audit-logs as the **cookie's** principal — send two principals at once, diff executing-vs-logged identity (CVE-2026-82355); logout revokes **only the `_token` cookie**, bearer tokens survive for full TTL — replay-after-logout on every credential transport (CVE-2026-86473); count-query missing the row filter → `total_entries` hidden-Dag oracle (CVE-2026-75158). MISP octet: login security controls gated on **POST/PUT only** → any other verb skips bruteforce-block + OTP 2FA + logging (CVE-2026-94379); read-only API key restores full account perms in one call (CVE-2026-94381); `save()` without unsetting client `id` where **sibling loops unset it** → cross-event report reparent (CVE-2026-94374); non-XML-content XML import SSRF + galaxy-name sprintf XSS. + Dogtag **lexicographic ACL tie-break** (wildcard beats specific literal, CVE-2026-80110), Hatchet **empty-`state` sentinel accepted** → login-CSRF (CVE-2026-61687), MINA fix landed on **one branch only** — "fixed" versions still vulnerable (CVE-2026-94301, 9.8) (16 GHSAs)](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md)



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
