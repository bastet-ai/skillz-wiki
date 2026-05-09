# AVideo session, CSRF, SQL, and race-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a WWBN AVideo batch updated on **2026-05-09**.

This batch is durable because self-hosted media platforms often put admin JSON endpoints, live-ingest callbacks, wallet ledgers, remote media download helpers, and PHP sessions behind different assumptions. The operator lesson is to treat each state-changing or filesystem-touching endpoint as its own boundary, even when it lives in an authenticated app.

## Advisories covered

- **ReceiveImage path traversal bypass** — [GHSA-m63r-m9jh-3vc6](https://github.com/advisories/GHSA-m63r-m9jh-3vc6): the prior fix checked only the URL path component, while later local-file handling parsed the full URL string; traversal payloads in the query string could still reach `/videos/../../`-style local reads. Affects `wwbn/avideo <= 29.0`; no patched version was listed in GitHub metadata at scan time.
- **Admin JSON CSRF batch** — [GHSA-ffw8-fwxp-h64w](https://github.com/advisories/GHSA-ffw8-fwxp-h64w): category create/update/delete and plugin update-script endpoints performed state changes with role checks but without the global CSRF token or untrusted-request guard. Affects `wwbn/avideo <= 29.0`; no patched version was listed.
- **YPTWallet balance TOCTOU** — [GHSA-h54m-c522-h6qr](https://github.com/advisories/GHSA-h54m-c522-h6qr): concurrent transfers could read the same sender balance and credit recipients multiple times without equivalent debits because the wallet update lacked transaction/row-locking semantics. Affects `wwbn/avideo <= 26.0`; no patched version was listed.
- **GET `PHPSESSID` session fixation** — [GHSA-x3pr-vrhq-vq43](https://github.com/advisories/GHSA-x3pr-vrhq-vq43): attacker-controlled session IDs accepted from the URL, endpoint-specific regeneration bypass behavior, and disabled login-time regeneration could let an attacker fix a victim session before authentication. Affects `wwbn/avideo <= 26.0`; no patched version was listed.
- **RTMP `on_publish` blind SQL injection** — [GHSA-8p58-35c3-ccxx](https://github.com/advisories/GHSA-8p58-35c3-ccxx): unauthenticated live-ingest callback input reached SQL queries without parameter binding; stream-name filtering removed only `&` and `=`. Affects `wwbn/avideo <= 26.0`; no patched version was listed.

## Operator triage

1. Treat exposed AVideo instances as high priority when live streaming, wallet, remote encoder/image receive, or admin plugin/category features are enabled.
2. Restrict `plugin/Live/on_publish.php` to trusted RTMP ingress hosts and review logs for long response times, SQL metacharacters, and unusual `name` values.
3. Disable or firewall ReceiveImage-style local/remote media pull helpers until canonical path validation checks the same value the file reader consumes.
4. Review category, plugin-update, wallet-transfer, login, and session logs for cross-site request timing, repeated concurrent transfers, attacker-chosen `PHPSESSID` values, and admin actions following external referrers.
5. Rotate session cookies, clone/API/payment/mail/database credentials, and admin passwords if SQL injection, filesystem read, or session fixation indicators are present.

## Durable controls

- Validate canonical paths at the last filesystem boundary using the exact decoded value that will be opened; do not validate one URL component and consume another.
- Require CSRF tokens or Fetch Metadata/origin checks on every state-changing JSON endpoint, including plugin/admin maintenance routes.
- Regenerate session IDs after authentication and reject session identifiers supplied in URLs.
- Put financial and quota-affecting updates inside database transactions with row-level locks or atomic compare-and-swap operations.
- Live ingest callbacks should be authenticated, source-restricted, and query only through parameterized statements.
