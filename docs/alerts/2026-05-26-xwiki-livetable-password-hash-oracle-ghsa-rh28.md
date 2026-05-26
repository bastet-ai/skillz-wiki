# XWiki LiveTable password-hash oracle boundary (GHSA-rh28-mqj4-8x59, 2026-05-26)

**Signal:** GitHub published `GHSA-rh28-mqj4-8x59` / `CVE-2026-48048` for XWiki Platform LiveTable results. XWiki notes that the previous fix for password and email field filtering was incomplete: with modified `LiveTableResults` parameters, an attacker can still infer password salt/hash material one bit at a time, reconstructing the full value with 768 requests.

The durable operator value is the chain shape: **query/listing endpoint + attacker-controlled column metadata + per-property class confusion = sensitive field oracle**. Treat this as a reusable authorization and data-boundary testing pattern, not just an XWiki version check.

## Why it matters for authorized testing

This is useful when an assessment includes XWiki, custom XClasses, tenant wiki boundaries, account recovery posture, or password-hash exposure impact analysis. It also generalizes to any application where a table/list endpoint allows callers to provide both field names and field-class metadata.

Reusable lessons:

1. **List endpoints can become data oracles.** Even if password fields are not returned directly, sort/filter/count behavior can leak enough information to reconstruct secrets.
2. **Field type checks must resolve the effective property class.** The patch switches the filtering logic from the outer class lookup to `#livetable_getPropertyClassAndType($colname)`, then checks the resolved property class before adding a column to the query.
3. **Partial fixes need variant regression.** If a prior patch blocked `password` under one parameter shape, retest alternative class-per-property parameters such as `password_class` plus `collist`.
4. **Hash disclosure is a credential-boundary finding.** The immediate proof is data extraction, but the report should explain downstream offline cracking, credential reuse, and tenant/account pivot risk without attempting cracking unless explicitly authorized.

## Validation workflow

Only perform active validation in a lab, staging clone, or an explicitly approved exploit-validation window. Avoid high-volume extraction on production systems unless the customer has approved the exact request budget.

### Recon

1. Fingerprint XWiki and the affected package range for `org.xwiki.platform:xwiki-platform-livetable-ui`:
   - `>= 6.2.1, < 16.10.17`
   - `>= 17.0.0-rc-1, < 17.4.9`
   - `>= 17.5.0-rc-1, < 17.10.3`
2. Identify reachable LiveTable-backed pages and whether the target exposes `LiveTableResults` behavior to anonymous users, normal users, or wiki-scoped roles.
3. Inventory custom XClasses with sensitive fields, especially password-like, token-like, and email fields.
4. Confirm whether prior hardening only filtered direct password columns or also resolved class-per-property metadata.

### Safe proof shape

Prefer a disposable lab page or customer-provided test XClass:

1. Create a benign XClass with a synthetic `Password` field containing a known marker value.
2. Query the LiveTable results path with controlled `collist` and per-property class parameters that reference the password field.
3. Validate whether response behavior changes based on guessed bit/character predicates for that synthetic field.
4. Stop after proving oracle behavior against the marker; do not reconstruct real user hashes unless the rules of engagement explicitly authorize secret extraction.

Collect evidence that is sufficient for a report:

- affected XWiki version and package range;
- authenticated role required, if any;
- target wiki/subwiki context;
- parameter shape used for the proof;
- response behavior that demonstrates the oracle;
- request count used for the minimal proof;
- confirmation that real user password hashes were not extracted, or explicit authorization if they were.

## Variant checks

- `collist` values that reference sensitive fields indirectly through class-per-property parameters.
- Password, email, token, API key, recovery-code, and custom secret field types.
- Main wiki versus subwiki class resolution.
- Anonymous, normal user, script user, subwiki admin, and main-wiki admin access levels.
- Count-only, sort, filter, pagination, and error-message differences that can expose predicate truth.
- Previous-fix bypasses where the outer class is safe but the per-property class resolves to a sensitive field.

## Reporting heuristic

A strong finding should frame this as a **sensitive-field oracle through metadata-controlled list queries**. Include:

- exact endpoint/page and parameter names;
- affected class and field type;
- whether the oracle reveals bits, characters, counts, or ordering;
- estimated request count for full extraction and the lower request count used for safe proof;
- credential impact: offline cracking exposure, password reuse, and account takeover prerequisites;
- tenant boundary notes if a subwiki or low-scope user can query another security domain;
- patch reference showing the need to resolve the effective property class before adding fields to the LiveTable query.

## Non-signal this hour

Other checked sources did not add a fresh promotable item beyond already-covered material: CISA KEV advanced to catalog `2026.05.26` with the already-promoted LiteSpeed cPanel plugin privilege-escalation entry; PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, and Disclosed did not surface a new durable offensive-operator delta.

## Sources

- [GitHub Advisory Database: XWiki LiveTable password-hash oracle (`GHSA-rh28-mqj4-8x59`)](https://github.com/advisories/GHSA-rh28-mqj4-8x59)
- [XWiki Platform advisory: LiveTable results allow reconstructing password hashes](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rh28-mqj4-8x59)
- [XWiki Jira `XWIKI-23875`: LiveTable may use the wrong property class for password and email checks](https://jira.xwiki.org/browse/XWIKI-23875)
- [Patch commit `c444271`: use resolved property class/type for LiveTable password and email checks](https://github.com/xwiki/xwiki-platform/commit/c4442716b02ffcdaa9d5e703b1db6203e36456fa)
