# Mirasvit Cache Warmer `CacheWarmer` cookie deserialization boundary

Sources: CISA KEV catalog `2026.06.03` added [CVE-2026-45247 in the KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). The CVE is corroborated by the [CVE Program API record](https://cveawg.mitre.org/api/cve/CVE-2026-45247), the [NVD API record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-45247), Sansec's technical write-up [Critical vulnerability in Mirasvit Cache Warmer for Magento](https://sansec.io/research/mirasvit-cache-warmer-object-injection), [VulnCheck's advisory](https://www.vulncheck.com/advisories/mirasvit-cache-warmer-for-magento-php-object-injection), and the [Mirasvit Cache Warmer changelog](https://mirasvit.com/package/changelog/?package=mirasvit/module-cache-warmer).

This is durable for operators because it turns a current KEV entry into a reusable Magento/Adobe Commerce assessment question: can an unauthenticated storefront request reach PHP `unserialize()` through a third-party cache-warming cookie before any admin session, route authorization, or warmer-only trust boundary is enforced?

## What changed

- **CISA KEV signal** — CISA added CVE-2026-45247 to the known-exploited catalog on 2026-06-03.
- **Affected component** — CVE records identify Mirasvit Full Page Cache Warmer for Magento 2 versions before `1.11.12` as affected.
- **Vulnerable primitive** — the `CacheWarmer` cookie can carry attacker-controlled serialized PHP object data to native `unserialize()`. Sansec describes this as reachable on ordinary storefront requests, not only Mirasvit's own warmer traffic.
- **Operator takeaway** — during Magento/Adobe Commerce testing, third-party performance extensions and cache-warming cookies belong in the unauthenticated attack-surface map, not only in authenticated admin-extension review.

## When to use this check

Use this during authorized Magento, Adobe Commerce, ecommerce, CDN-fronted storefront, or third-party-extension assessments where the rules of engagement allow application fingerprinting and passive log/evidence review.

Good targets:

- Magento/Adobe Commerce storefronts with Mirasvit modules installed;
- stores that expose frontend caching, warmer, optimizer, or performance-extension signals;
- multi-tenant ecommerce platforms where a storefront RCE would cross from public web traffic to host, database, payment, or admin infrastructure;
- CDN/WAF-fronted stores where extension fingerprints may be hidden but source, deployment manifests, or access logs are in scope.

Do **not** send public exploit payloads, gadget-chain payloads, or object-injection probes to production storefronts. The validation below is designed to prove reachability and exposure without invoking PHP object deserialization.

## Read-only extension and version fingerprinting

Prefer source, deployment, or package evidence when it is in scope.

```bash
# From an authorized Magento code checkout or deployment artifact.
find app/code vendor -maxdepth 5 -iname '*Cache*Warmer*' -o -iname '*Mirasvit*' 2>/dev/null

grep -R "mirasvit/module-cache-warmer\|Mirasvit.*CacheWarmer" \
  composer.json composer.lock app/etc/config.php app/etc/env.php app/code vendor 2>/dev/null | head -100

# Composer lock version check: affected if mirasvit/module-cache-warmer < 1.11.12.
jq -r '.packages[]? | select(.name=="mirasvit/module-cache-warmer") | [.name,.version] | @tsv' composer.lock 2>/dev/null
```

If `jq` is unavailable, capture the relevant `composer.lock` package block and record the exact version. Avoid collecting credentials from `app/etc/env.php`; only retain module names, versions, and enabled/disabled status.

Magento module-state evidence is useful when CLI access is explicitly in scope:

```bash
# Run from the Magento application root with the same restrictions as any other app CLI test.
php bin/magento module:status 2>/dev/null | grep -i 'Mirasvit\|Cache.*Warmer' || true
php bin/magento module:status --enabled 2>/dev/null | grep -i 'Mirasvit\|Cache.*Warmer' || true
```

## Storefront and CDN recon

Public HTTP fingerprints are often weak because CDNs, themes, and minifiers hide extension assets. Use them to prioritize, not as sole proof.

```bash
# Replace targets.txt with authorized storefront origins or URLs.
httpx -l targets.txt -silent -status-code -title -tech-detect -follow-redirects \
  -H 'User-Agent: SkillzWiki-Magento-Recon/authorized'

# Look for Magento/Adobe Commerce signals without forcing extension behavior.
while read -r url; do
  printf '\n## %s\n' "$url"
  curl -skI --max-time 10 "$url" | grep -Ei 'x-magento|x-cache|fastly|varnish|set-cookie|server|x-powered-by' || true
done < targets.txt
```

High-signal public clues include Magento cookies (`PHPSESSID`, `form_key`, store/currency cookies), `X-Magento-*` headers, Magento static asset paths, Mirasvit asset/module names in page source, or a customer-provided extension inventory. Do not treat absence of these clues as proof of safety.

## Passive `CacheWarmer` cookie evidence

Sansec published a request-signature heuristic: storefront requests carrying a `CacheWarmer` cookie whose value contains `CacheWarmer:` followed by base64-like serialized object prefixes such as `Tz`, `Qz`, or `YT` are high-signal exploitation attempts. For operator validation, use that signature in logs supplied by the customer or in a lab capture; do not generate exploit traffic against production.

```bash
# Review authorized web/CDN logs for the cookie boundary without printing full cookie values.
# Input examples: nginx/access.log, Apache logs, CDN exports, or WAF request logs.
grep -Eio 'CacheWarmer:[A-Za-z0-9+/=]{0,80}' access.log* 2>/dev/null |
  sed -E 's/(CacheWarmer:)(.{0,12}).*/\1\2...[redacted]/' |
  sort -u

# Higher-signal Sansec-style marker check; emits only line numbers and redacted markers.
grep -En 'Cookie:.*CacheWarmer:(Tz|Qz|YT)|CacheWarmer=(Tz|Qz|YT)|CacheWarmer%3A(Tz|Qz|YT)' access.log* 2>/dev/null |
  sed -E 's/(CacheWarmer(:|=|%3A)(Tz|Qz|YT))[^ ;&]*/\1...[redacted]/g'
```

Evidence quality improves when you can correlate:

- affected Mirasvit Cache Warmer version `< 1.11.12`;
- public storefront route hit with a `CacheWarmer` cookie;
- request reached Magento/PHP rather than being blocked at CDN/WAF;
- application, WAF, or PHP logs show deserialization-related errors after the request;
- no authentication, admin session, or warmer-origin allowlist was required for the route.

## Lab-only reachability testing

If the customer requires active proof, keep it in a disposable lab clone or an explicitly approved staging target. The goal is to prove that the application consumes the cookie, not to execute code.

Safe lab pattern:

1. Clone the affected Magento app and install the same Mirasvit Cache Warmer version.
2. Enable verbose application logging in the lab.
3. Send a non-gadget, inert malformed `CacheWarmer` cookie to a harmless storefront route.
4. Confirm the lab logs show the vulnerable parser path attempting to process the cookie.
5. Stop before gadget-chain construction, command execution, file writes, or credential access.

Do not include payload strings, gadget-chain class names, shell output, webshell paths, or production cookie values in the public report or wiki evidence.

## Reporting heuristics

- Lead with the boundary: “unauthenticated storefront request can reach PHP object deserialization through the Mirasvit `CacheWarmer` cookie.”
- Include Magento/Adobe Commerce version, Mirasvit package name, exact module version, route tested or log source, and whether a CDN/WAF forwarded the cookie to origin.
- Separate **affected install evidence** from **exploit-attempt evidence**. A vulnerable version is enough to prioritize; a Sansec-style cookie marker in logs is stronger evidence of active exploitation.
- Keep log excerpts minimal and redacted. Show the cookie name and signature prefix only, never full payloads, session cookies, customer data, or backend paths.
- If the finding depends on source review, cite the package/version and the reachable unauthenticated request path rather than publishing deserialization payloads.

## Notes on skipped and unchanged sources

- GitHub Advisory Database latest reviewed advisories remained the Azure Key Vault Keys Java, ruby-jwt, Thrift, Vert.x, Bootstrap, Redshift, and camel-infinispan set already promoted, processed, or covered by existing guidance.
- PortSwigger stayed on the Top 10 web hacking techniques of 2025; Trail of Bits stayed on the already-promoted skill-distribution research; ProjectDiscovery stayed on the Neo agent-architecture post; GitHub Security Blog stayed GHES signing-key rotation/IR-oriented; Disclosed returned lander-only/Emma Legal content.
