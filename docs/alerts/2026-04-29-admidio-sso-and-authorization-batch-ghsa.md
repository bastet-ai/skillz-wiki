# Admidio SSO, authorization, path traversal, and XSS batch (GHSA-25cw-98hg-g3cg / GHSA-p9w9-87c8-m235 / GHSA-9xx5-cv6j-x533 / GHSA-rh3w-4ccx-prf9 / GHSA-m3vp-3jjm-gpmx / GHSA-m9h6-8pqm-xrhf and related)

**Signal:** GitHub Security Advisories published **2026-04-29**. Admidio fixed a large set of identity, authorization, file-read, and UI injection issues in `admidio/admidio`.

## What it is
The batch affects Admidio `<= 5.0.8`; fixed version is `5.0.9`.

High-signal issues include:

- `GHSA-25cw-98hg-g3cg` / `CVE-2026-41669`: SAML signature validation results are ignored, allowing forged AuthnRequests and LogoutRequests.
- `GHSA-p9w9-87c8-m235` / `CVE-2026-41670`: SAML responses are sent to an unvalidated attacker-controlled Assertion Consumer Service URL from AuthnRequest.
- `GHSA-9xx5-cv6j-x533` / `CVE-2026-41671`: OIDC introspection always returns `active: true`, and revocation reports success without revoking tokens.
- `GHSA-rh3w-4ccx-prf9` / `CVE-2026-41660`: inverted 2FA reset authorization lets certain profile editors strip administrator TOTP.
- `GHSA-m3vp-3jjm-gpmx` / `CVE-2026-41655`: ECard preview path traversal can read arbitrary server files, including database credentials.
- `GHSA-m9h6-8pqm-xrhf` / `CVE-2026-41656`: document add mode path traversal can register arbitrary server files into accessible document folders.
- `GHSA-gq27-fc8w-vcmp` / `CVE-2026-41661`: reflected XSS through square-bracket-to-tag placeholder conversion.
- `GHSA-xqv4-xm7h-52cv` / `CVE-2026-41658`: inventory destructive endpoints miss backend authorization checks.
- `GHSA-g8p8-94f2-28gr` / `CVE-2026-41657`: contacts data endpoint can expose cross-organization member data through weaker backend checks.
- `GHSA-c7xm-r6vj-8vg6` / `CVE-2026-41662`, `GHSA-rw74-vc9h-534j` / `CVE-2026-41663`, and `GHSA-68pr-7prh-mpv4` / `CVE-2026-41659` add admin-lockout, CSRF, and hidden-profile-field oracle risks.

References:

- <https://github.com/advisories/GHSA-25cw-98hg-g3cg>
- <https://github.com/advisories/GHSA-p9w9-87c8-m235>
- <https://github.com/advisories/GHSA-9xx5-cv6j-x533>
- <https://github.com/advisories/GHSA-rh3w-4ccx-prf9>
- <https://github.com/advisories/GHSA-m3vp-3jjm-gpmx>
- <https://github.com/advisories/GHSA-m9h6-8pqm-xrhf>
- <https://github.com/advisories/GHSA-gq27-fc8w-vcmp>
- <https://github.com/advisories/GHSA-xqv4-xm7h-52cv>
- <https://github.com/advisories/GHSA-g8p8-94f2-28gr>

## Triage
1. Identify Admidio deployments, especially those acting as SAML IdP or OIDC provider for other applications.
2. Inventory service-provider clients and resource servers that trust Admidio for assertions or token introspection.
3. Review whether `adm_my_files/config.php`, database credentials, backups, or document folders may have been exposed through path traversal workflows.
4. Identify non-admin group leaders/profile editors and users with inventory or contact-module access.
5. Check whether hidden profile fields contain sensitive PII that could have been inferred by search.

## Mitigation
- Upgrade Admidio to `5.0.9` or later.
- Rotate SAML/OIDC secrets and invalidate sessions if the IdP was exposed to untrusted users or public traffic.
- Require strict ACS URL matching, enforce SAML signature validation as a hard gate, and make OIDC introspection validate token state and caller authentication.
- Move secrets out of web-readable paths where possible and verify file-serving/document-registration controls.
- Put backend authorization checks on every destructive or cross-tenant data endpoint; UI-only button hiding is not security.

## Detection ideas
- Review SAML logs for AuthnRequests with unexpected `AssertionConsumerServiceURL` values or unsigned/invalidly signed messages accepted as valid.
- Search web logs for path traversal strings in `ecard_template`, document `name`, and document/file endpoints.
- Look for calls to OIDC introspection with fabricated or expired tokens that still returned active.
- Check admin 2FA reset events, role membership removals, inventory deletes, and cross-organization contact exports.
- Inspect access logs for reflected XSS payloads using square brackets such as `[script]` rather than literal angle brackets.

## Durable lesson
SSO and admin modules need fail-closed validation at the backend boundary. Do not let UI state, comments about exceptions, or placeholder encoding become the security control.
