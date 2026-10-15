# pfSense CE privilege-ladder wave: per-page privileges as root-exec channels via config, crontab, shell-interpolation, and file:// legs

**Event in one line:** On 2026-10-15 Netgate published an ~18-GHSA coordinated wave for pfSense CE (through 2.9.0): nearly every leg is a **narrow, low-tier WebGUI privilege** (PPPs Edit, Wireless Edit, VIP Edit, Limiter, Gateway Edit, Captive Portal HA, IPsec Mobile, PPPoE Server Edit, DNS Resolver ACL, Dynamic DNS client) that reaches **root code execution** through one of four reusable sink classes — config-file injection into a downstream parser that executes (`strongswan.conf` start-scripts, `mpd5` up-scripts/secrets, `sshguard.conf`, `unbound.conf`, `/etc/crontab`), unescaped interpolation into `ifconfig`/`dpinger`/`pfctl`/`dnctl` shell commands, a `file://` URL whose fetched contents leak through the system log, and a `config.xml` restore path that **ignores the deny-privilege that should block it**.

**Why this is durable operator content:** pfSense ships in SMB/firewall engagements constantly, often reachable from guest/outbound VLANs with a modest helpdesk-tier credential. The wave is a vendor-published inventory of *which low-tier privilege buys which root path*, and the sink classes generalize to every embedded/admin-panel product that writes user fields into config files or shell command strings.

## Primary sources

- GitHub advisories (all published 2026-10-15 21:36Z, pfSense CE ≤2.9.0 unless noted): [GHSA-cx43-pf3x-hc6x](https://github.com/advisories/GHSA-cx43-pf3x-hc6x) crontab injection, [GHSA-743j-3p3m-6h73](https://github.com/advisories/GHSA-743j-3p3m-6h73) strongswan start-scripts, [GHSA-28v9-q2x4-wjw8](https://github.com/advisories/GHSA-28v9-q2x4-wjw8) + [GHSA-gg6q-95gx-p8r8](https://github.com/advisories/GHSA-gg6q-95gx-p8r8) mpd5 legs, [GHSA-fm76-5wvr-6cv2](https://github.com/advisories/GHSA-fm76-5wvr-6cv2) sshguard.conf, [GHSA-3c6h-8mvp-vqx3](https://github.com/advisories/GHSA-3c6h-8mvp-vqx3) php.ini via zoneinfo, [GHSA-c3v6-7g6h-r7q8](https://github.com/advisories/GHSA-c3v6-7g6h-r7q8) file:// DyDNS read, [GHSA-prh2-rh73-jcp7](https://github.com/advisories/GHSA-prh2-rh73-jcp7) config-restore deny-bypass, [GHSA-5w5g-f2w6-c5hp](https://github.com/advisories/GHSA-5w5g-f2w6-c5hp)/[GHSA-qcp6-4768-v6qq](https://github.com/advisories/GHSA-qcp6-4768-v6qq)/[GHSA-fffm-6286-c3r5](https://github.com/advisories/GHSA-fffm-6286-c3r5)/[GHSA-224g-fpr5-96gw](https://github.com/advisories/GHSA-224g-fpr5-96gw)/[GHSA-j7pj-3cmw-7qqc](https://github.com/advisories/GHSA-j7pj-3cmw-7qqc) shell-interp legs, [GHSA-x2xf-vqvc-49xv](https://github.com/advisories/GHSA-x2xf-vqvc-49xv) OpenVPN username, [GHSA-643j-4p8v-85c8](https://github.com/advisories/GHSA-643j-4p8v-85c8) learn-address (unbound user), [GHSA-xf3x-9wqm-925c](https://github.com/advisories/GHSA-xf3x-9wqm-925c) XMLRPC-sync trust, [GHSA-4m9r-jxrh-x66q](https://github.com/advisories/GHSA-4m9r-jxrh-x66q)/[GHSA-3pxq-gxxr-7p9c](https://github.com/advisories/GHSA-3pxq-gxxr-7p9c) Unbound CRLF, [GHSA-3vw7-4qg6-g75v](https://github.com/advisories/GHSA-3vw7-4qg6-g75v)/[GHSA-hvrf-cf2c-3rqh](https://github.com/advisories/GHSA-hvrf-cf2c-3rqh) XSS legs

## The ladder, by sink class (as published)

### Class 1 — config-file injection into a downstream executor

The user field is not executed directly; it is written into a config file that a root process later **parses with executable semantics**. The newline/quote is the whole exploit.

- **strongswan.conf via IPsec Mobile-user login banner** (743j, 7.2): a single-line banner containing `}` closes the unquoted `attr` value early and defines `charon.start-scripts` — charon runs them as **root on restart**.
- **mpd5 config via L2TP/PPPoE RADIUS shared secret** (28v9, 7.2): quote + newline in the secret appends an `up-script` executed as root when a session starts. Sibling (gg6q, 7.2): newline in the PPPoE **username** adds an `mpd.secret` line whose secret begins with `!` — mpd5 executes `!`-prefixed secrets as root on client auth. Two entry points, one parser feature: *mpd5 secrets starting with `!` are commands*.
- **/etc/crontab via PPP interface fields** (cx43, 7.2): newlines in `ptpid`/reset hour/minute are written **unescaped** by `configure_cron()` — scheduled root commands.
- **sshguard.conf via Login Protection fields** (fm76, 7.2): newline or `$(...)` in threshold/block-time values, conf sourced as root on restart.
- **php.ini via timezone value** (3c6h, 6.6): quote + newline in General Setup timezone adds `auto_prepend_file=/var/db/zoneinfo`; plant PHP in the zoneinfo file, get **PHP as root** after php.ini regenerates at boot/php-fpm restart. Multi-step but fully unprivileged-to-root.
- **unbound.conf via CRLF in ACL name/action or sock_queue_timeout** (4m9r, 3pxq): inject `local-data`, `local-zone`, `forward-zone` — not RCE, but **attacker-controlled DNS answers for every LAN client** (phishing/redirection pivot from a DNS-ACL-tier credential).

### Class 2 — unescaped interpolation into shell commands

- Interface-name legs: QinQ parent `if` value (5w5g), wireless parent like `ath0;<cmd>` (qcp6) → `ifconfig` via `interface_wireless_clone()`; CARP VHID metacharacters (fffm) → `ifconfig`/`get_carp_interface_status()`; gateway monitor-IP IPv6 **zone index** (j7pj) → unescaped into `dpinger`.
- Limiter hidden `number` field (224g): tamper the value on edit, then **delete** the limiter — `delete_queue()` passes the stale unquoted value to `dnctl` via `/bin/sh` as root (store-then-trigger with the trigger being a *delete* verb).
- OpenVPN `openvpn.connect_async.sh` (x2xf): RADIUS/Ldap **usernames** with quotes/metacharacters break out of the eval'd `pfctl` anchor name — *VPN authentication itself is the injection vector*, root.
- `openvpn.learn-address.sh` (643j): cert CN/username into `su -c` strings — command exec as the `unbound` user from a plain VPN-client posture.
- Captive Portal HA sync (xf3x): `backwardsyncip` pointed at a **malicious XMLRPC server** whose `connected_users` ip/mac fields carry metacharacters → `pfctl` unescaped. The trust is in the *peer response*, not a form field — same genealogy as the Oct 14 Apprise "attacker controls the response, not the URL" leg.

### Class 3 — file:// as an authenticated arbitrary-file-read shape

- Dynamic DNS custom Update URL = `file:///conf/config.xml` with a deliberately **non-matching Result Match string** so `_checkStatus()` logs the fetched file contents to the system log (c3v6, 4.9). Read root-owned files (config.xml secrets, `/etc/master.passwd`) **through the log viewer** with only a DyDNS-client privilege. Same `file://`-in-outbound-URL shape as SimplePie CVE-2026-111234 the same day (feed redirect/autodiscovery `Location: file:///...` → `file_get_contents()` server-file read — any RSS/aggregator ingestion in any product).

### Class 4 — the deny-privilege that isn't enforced

- Read-only WebGUI users holding *page* privileges for `uploadconfig.php`/`diag_confbak.php`/`diag_backup.php`/`services_acb.php` can **replace config.xml** because `config_restore()`/`config_install()` never consult the `User - Config: Deny Config Write` privilege (prh2, 7.2). Install a crafted config.xml (which embeds shells/credentials/PHP via the same Class-1 fields) → root after reload/reboot. Rule: **deny-privileges are the leakiest part of allow+deny hybrids — enumerate every verb that mutates the same object the deny-privilege names and check which ones actually consult it.**

## Hunt patterns this generalizes

1. **Admin-panel fields are config-file content.** For any embedded web admin that regenerates daemons' configs, treat every free-text field written into `.conf` output as an injection site: probe newline/quote/brace tolerance per field, then identify the parser's *executable features* (start-scripts, `!`-secrets, `auto_prepend_file`, crontab lines). The vendor's own advisory wave is an index of which fields lack validation.
2. **Store-then-trigger, trigger sometimes = delete.** Several legs only fire on a later action (limiter delete, CARP status render, session start, restart, reboot). After saving a canary payload, exercise **every verb on the object** — including delete — and inspect what command the next natural lifecycle event builds.
3. **Privilege-to-root ladder map before engagement.** If a client engagement grants you any pfSense WebGUI role, the wave gives the exact per-privilege path: Interfaces-PPPs/Wireless/VIP/Limiter/Gateway-Edit, IPsec-Mobile, PPPoE/L2TP-Edit, Captive-Portal-HA, DNS-Resolver-ACL/Advanced, DyDNS → root. Same mapping exercise is worth doing for every niche admin panel: grep the codebase (pfSense is open source) for `exec2|mwexec|exec` consumers of `config_get_path` values.
4. **Peer-response injection**: any "sync/backup/HA peer" setting converts a *server response* into shell material — point the peer setting at your own server and fuzz the response fields, not just local form fields.
5. **file:// fetch + error/log echo = read primitive without an explicit read endpoint.** Sweep any URL field (webhook, update URL, feed URL, import URL) with `file://` + a guaranteed-mismatch/forced-error path and read the logs/error text back.

## Authorized validation boundary

All proof on lab pfSense (or the customer's explicitly approved instance): inert marker payloads (touch-marker commands, non-destructive `local-data` TXT records you can resolve back, `file://` reads of synthetic canary files — never `/etc/master.passwd` on a live box), no config.xml replacement on production, restarts only in windows the client approves. Do not test OpenVPN username injection or HA-sync peer legs against production VPN concentrators without explicit scope — both fire on live auth events.

## Related wiki pages

- [Ivanti Connect Secure exploited chain](2026-10-13-ivanti-connect-secure-chain-x-dscgi-path-dispatch-split-write-delete-race-and-edge-device-post-exploitation.md) — perimeter appliance class, dispatch-vs-config trust
- [Shell-quote and newline operator boundaries](2026-06-09-shell-quote-newline-operator-boundary-ghsa.md) — the quote-breakout genealogy this wave extends into config-parser features
- [July 30 URL-policy and tenant boundaries](2026-07-30-url-policy-tenant-oauth-boundaries-ghsa.md) — URL-scheme (`file://`) policy class
