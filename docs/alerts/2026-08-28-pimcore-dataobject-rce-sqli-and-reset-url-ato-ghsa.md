# Pimcore DataObject RCE, Hotspotimage PHP deserialization, Studio SQLi, and reset-URL ATO, operator…

**Date reviewed:** 2026-08-28
**Advisories:** [GHSA-9x44-4gxf-8c25 / CVE-2026-55634](https://github.com/advisories/GHSA-9x44-4gxf-8c25) (critical, RCE), [GHSA-w23p-wrp7-ch38 / CVE-2026-55220](https://github.com/advisories/GHSA-w23p-wrp7-ch38) (critical, PHP object injection), [GHSA-f97c-ph8j-8vff / CVE-2026-55212](https://github.com/advisories/GHSA-f97c-ph8j-8vff) (high, privilege escalation), [GHSA-79cw-hfcc-7mw9 / CVE-2026-55208](https://github.com/advisories/GHSA-79cw-hfcc-7mw9) (high, blind SQLi), [GHSA-h854-c3m3-mh5v / CVE-2026-55207](https://github.com/advisories/GHSA-h854-c3m3-mh5v) (high, account takeover). All in `pimcore/pimcore` and/or `pimcore/studio-backend-bundle`.

Five independent primitives from one product in one wave, each reusable across CMS/low-code/admin-surface hunting:

| Class | Pattern | Why it matters |
| --- | --- | --- |
| RCE | Structured identifier (field name) → generated source code, no allowlist | Any CMS/low-code engine that compiles user-defined schemas into PHP/SQL is a target |
| PHP OI | Unrestricted `unserialize()` over a persisted column | Stored-bytes → load-time code execution; write-once, fire-on-load |
| Privesc | Structural admin operation guarded by a weaker permission + no format validation | Class/table creation = structural change; `objects` vs `classes` guard drift |
| Blind SQLi | User-supplied column name interpolated into SQL with only backtick wrapping | Named parameters don't protect identifiers; backtick breakout + status-code oracle |
| ATO | Unauthenticated reset flow accepts attacker-controlled URL; token appended to it | Token-login endpoint explicitly disables 2FA, the reset flow *is* the auth bypass |

## 1. DataObject class-definition field name → RCE (GHSA-9x44-4gxf-8c25)

Pimcore generates a PHP class file for every DataObject class. The property block is built in `lib/DataObject/ClassBuilder/FieldDefinitionPropertiesBuilder.php`:

```php
protected $<fieldName>;   // <fieldName> concatenated with no identifier allowlist
```

A user holding only the ordinary `objects` (DataObjects) permission can import a class definition whose field name closes the property and injects arbitrary PHP into the generated class file. The same unvalidated field name is also concatenated into `ALTER TABLE` DDL (`ADD COLUMN`/`ADD INDEX`), giving a parallel SQL-injection primitive. This is a sibling of CVE-2026-5394 (composite-index column SQL injection); that fix hardened only the composite-index path and left the property builder open.

The advisory's PoC is **sink-confirmed + chain-reasoned** (runtime-confirmed in an isolated harness): the real builder emits attacker PHP into the generated class body, the class loads, and its `__construct()` executes a shell command. The remaining end-to-end links are reasoned from source but not run on a live Pimcore: (a) the Studio import path (`generateLayoutTreeFromArray` → `save`) preserving the field name without transform/reject; (b) the persistent-field DDL step not aborting the save (addressed by the ≤64-byte gadget); and (c) Pimcore instantiating the object (`DataObject::getById()`) so `__construct()` fires. Treat the RCE as sink-confirmed, not as a fully-executed live exploit.

## 2. Hotspotimage `getDataFromResource()` unrestricted deserialization (GHSA-w23p-wrp7-ch38)

`Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage::getDataFromResource()` deserializes the `*__hotspots` object-store column through the `Pimcore\Tool\Serialize::unserialize()` wrapper **without a class allowlist** (the wrapper's `$allowedClasses` parameter defaults to `true`, i.e. fully unrestricted):

```php
public static function unserialize(?string $data = null, array|bool $allowedClasses = true): mixed
{
    if ($data === null || $data === '') { return $data; }
    return unserialize($data, ['allowed_classes' => $allowedClasses]);  // default true = unrestricted
}
```

Because the persistence layer always stores the column as PHP-`serialize()`d bytes, every load of a DataObject with a Hotspotimage (advanced image) field runs an unrestricted `unserialize()` over the stored value. An attacker who can write the `*__hotspots` column with crafted serialized bytes achieves PHP Object Injection (CWE-502). This is the **serialization leg** of the DataObject RCE: it requires write access to the column, but no class-allowlist defense is present, so any such write is weaponizable on the next object load.

Sibling marshallers with the identical fallback shape: `ImageGallery`, `Block`, `Video`. Affected: all maintained releases including `v2026.1.4` and `v12.3.8`.

## 3. Studio class-definition creation privilege escalation (GHSA-f97c-ph8j-8vff)

The Studio API class-definition creation endpoint in `pimcore/studio-backend-bundle` is guarded by the `objects` permission instead of the `classes` permission, allowing any standard editor-level user to create class definitions without admin privileges. Class-definition creation is a structural admin operation that generates new database tables and PHP class files. Additionally, the API layer performs no format validation on the `uid` field before passing it to the model layer, relying solely on downstream `ClassDefinition::saveClassInternal()` validation.

## 4. Studio `DateFilter` column-key blind SQLi (GHSA-79cw-hfcc-7mw9)

An authenticated user extracts the admin password hash and any other database content through a time-based blind SQL injection in the `DateFilter` column `key` parameter. `POST /pimcore-studio/api/website-settings` (and 11 other listing endpoints) accepts a `columnFilters` array where the `key` field is interpolated directly into SQL with only manual backtick wrapping. The `DateFilter` uses fixed named parameters (`:minTime`, `:maxTime`), so the injected column name is not subject to PDO named-parameter validation:

```php
$key = $column->getKey();  // user-controlled, no validation
$dateCondition = '`' . $key . '` ' . ' BETWEEN :minTime AND :maxTime';
$listing->addConditionParam($dateCondition, ['minTime' => $value, 'maxTime' => ...]);
```

Break out of the backtick quoting with a backtick character and append arbitrary SQL, including `SLEEP()` for time-based extraction and `IF()` subqueries for conditional data exfiltration. The same pattern appears in `src/Note/Service/FilterService.php`.

## 5. Unauthenticated account takeover via password-reset URL injection (GHSA-h854-c3m3-mh5v)

An unauthenticated attacker takes over any Pimcore admin account by sending a password-reset request with an attacker-controlled `resetPasswordUrl`. The server generates a real cryptographic recovery token, appends it to the attacker's URL, and emails the link to the victim. When the victim clicks the link, the token is sent to the attacker's server. The attacker then uses `POST /pimcore-studio/api/login/token` to authenticate as the victim with full admin privileges. Token login **explicitly disables two-factor authentication**, so even accounts with TOTP/Google Authenticator are compromised.

Root: the reset endpoint at `src/User/Controller/ResetPasswordController.php` (line 53) is public (`PUBLIC_STUDIO_API` voter) and the `ResetPassword` schema accepts `resetPasswordUrl` with zero validation, no URL scheme check, no domain allowlist, no comparison against the configured system domain.

## Durable operator value

1. **Schema-to-source compilers are a CMS class.** Any low-code/CMS that turns user-defined fields/labels into generated PHP, SQL DDL, or class files is a target. Enumerate every emission context and check the identifier allowlist. The DataObject property builder and the `ALTER TABLE` DDL share the same unvalidated field name, one bug, two primitives.
2. **Unrestricted `unserialize()` over a persisted column is write-once, fire-on-load.** If you have any write primitive into a DataObject store column (or an image-field metadata column), you have a deserialization sink on the next load. Sibling marshallers (`ImageGallery`, `Block`, `Video`) multiply the surface. Pair a write primitive here with an existing `__destruct`/`__wakeup`/`__toString` gadget in the autoloader.
3. **Guard drift on structural operations.** When a "create class / create table / create schema" endpoint is gated by a weaker permission than the matching read/delete route, that's a privilege-escalation probe. Report the exact permission on the UI route vs the API route.
4. **Backtick-wrapped identifiers are not parameterized.** Named PDO parameters protect *values*, not *identifiers*. Any user-supplied column/table/field name reaching SQL with only manual backtick wrapping is a breakout candidate. The status-code / response-time oracle (200 vs 404, `SLEEP` vs no-sleep) turns it into blind SQLi.
5. **The reset flow is the auth bypass when token-login disables 2FA.** An attacker-controlled reset URL that carries the recovery token out-of-band, plus a token-login endpoint that skips 2FA, is a complete unauthenticated ATO. This is the highest-leverage item in the wave: one email click → full admin.

## Replayable validation (lab / owned accounts only)

Preconditions: an authorized lab Pimcore instance (or a forked Studio deployment), a scoped editor-level account, a synthetic admin account for the ATO, and a redacting HTTP recorder. No production data, no real admin accounts, no real reset emails.

1. **Field-name RCE/SQLi (GHSA-9x44-4gxf-8c25 / 79cw-hfcc-7mw9).** Confirm the DataObject/Studio import path and the builder source. Use a benign field name that closes the property and echoes a canary (no shell). Capture the generated class file and the DDL. For the SQLi, use a backtick-breakout with `SLEEP(1)` vs no-sleep and record the differential. Do not read real hashes or exfiltrate production data.
2. **Deserialization (GHSA-w23p-wrp7-ch38).** In a lab with a denied/detected sink, write a harmless serialized marker to the `*__hotspots` column of a synthetic DataObject and confirm it deserializes on load (class-resolution evidence only). Do not deploy public gadget chains or trigger command execution.
3. **Privesc (GHSA-f97c-ph8j-8vff).** As an editor-level account, attempt class-definition creation via the Studio API and capture the accepted response + the created table/class. Compare against the `classes` permission the route should have required.
4. **Blind SQLi (GHSA-79cw-hfcc-7mw9).** Send a `DateFilter` `key` that breaks out with a boolean payload (`1' AND 1=1 --` vs `1' AND 1=2 --`) and record the two DAV/API status codes as the oracle. Extract only a single marker value from a synthetic table.
5. **Reset-URL ATO (GHSA-h854-c3m3-mh5v).** In the lab, point `resetPasswordUrl` at a lab listener, trigger a reset for a synthetic admin, capture that the token arrives at the lab listener, and confirm `POST /pimcore-studio/api/login/token` authenticates. Do not target real users or capture real tokens.

Evidence to capture: the exact builder/filter/service line, the affected Pimcore/Studio version, the minimal permission required, the generated class/DDL/SQL, the status-code oracle pair, and the reset-token-to-login path with the 2FA-disabled token-login endpoint. Redact all real credentials and tokens.

## Safe boundaries

- Authorized lab Pimcore/Studio deployment only; scoped synthetic accounts.
- No production data extraction, no real admin account compromise, no real reset emails, no public gadget-chain deployment.
- Report the exact emission/interpolation sink, the minimal permission, and the input-to-sink path with a patched/negative control.

## Sources

- [GitHub Advisory Database: Pimcore GHSA-9x44-4gxf-8c25 / CVE-2026-55634](https://github.com/advisories/GHSA-9x44-4gxf-8c25)
- [GitHub Advisory Database: Pimcore GHSA-w23p-wrp7-ch38 / CVE-2026-55220](https://github.com/advisories/GHSA-w23p-wrp7-ch38)
- [GitHub Advisory Database: Pimcore GHSA-f97c-ph8j-8vff / CVE-2026-55212](https://github.com/advisories/GHSA-f97c-ph8j-8vff)
- [GitHub Advisory Database: Pimcore GHSA-79cw-hfcc-7mw9 / CVE-2026-55208](https://github.com/advisories/GHSA-79cw-hfcc-7mw9)
- [GitHub Advisory Database: Pimcore GHSA-h854-c3m3-mh5v / CVE-2026-55207](https://github.com/advisories/GHSA-h854-c3m3-mh5v)
