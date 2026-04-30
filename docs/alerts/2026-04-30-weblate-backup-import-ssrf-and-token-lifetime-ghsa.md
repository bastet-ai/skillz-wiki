# Weblate backup-import SSRF and API token lifetime issues (GHSA-cwcx-382v-8m9g / GHSA-6j8j-4qp3-36p2)

**Signal:** GitHub Security Advisories published **2026-04-30**. Weblate fixed an authenticated SSRF path in project backup import plus API tokens that survived password changes.

## What it is
Two Weblate issues matter for hosted and delegated project-creation environments:

- `GHSA-cwcx-382v-8m9g` / CVE-2026-41654: a user with `project.add` could import a crafted backup ZIP whose component JSON contained a private-address or non-allow-listed `repo` URL. Bulk creation bypassed Django `full_clean()`, so `validate_repo_url` did not run; the URL was then written into Git config.
- `GHSA-6j8j-4qp3-36p2` / CVE-2026-41519: changing a password invalidated browser sessions but did not revoke DRF API tokens (`wlu_*`).

Affected package: pip `weblate < 5.17.1`. Fixed version: `5.17.1`.

References: <https://github.com/advisories/GHSA-cwcx-382v-8m9g>, <https://github.com/advisories/GHSA-6j8j-4qp3-36p2>

## Triage
1. Identify Weblate instances where untrusted users can create projects, start trials, or import backups.
2. Review imported backup archives and component repositories for private IPs, localhost, `file://`, `git://`, or other disallowed schemes.
3. For accounts with suspected compromise or password resets, enumerate and rotate API tokens.

## Mitigation
- Upgrade to Weblate `5.17.1` or later.
- Restrict `project.add` and backup import permissions to trusted users.
- Enforce outbound network controls around Weblate workers and Git operations.
- Revoke API tokens during password resets and incident response until all instances are patched.

## Detection ideas
- Hunt Git config and component metadata for repository URLs targeting internal ranges or unexpected schemes.
- Alert on backup imports followed by outbound connections to loopback, RFC1918, link-local, metadata, or non-standard Git schemes.
- Monitor continued API token use after password changes.

## Durable lesson
Validation bypasses often come from alternate object-creation paths. Importers, bulk inserts, and restore flows must run the same validators as UI/API create flows, and credential revocation must cover API tokens, not just browser sessions.
