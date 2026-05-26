# Weblate Mercurial repo-URL SSRF and file-enumeration primitive (GHSA-hfpv-mc5v-p9mm / CVE-2025-66407)

**Signal:** GitHub Security Advisories published **2026-05-26**. Weblate let authorized users turn a repository URL into a server-side fetch primitive when Mercurial was selected, including full-response retrieval for HTTP targets and existence-oracle behavior for `file://` paths.

## What it is

`GHSA-hfpv-mc5v-p9mm` / `CVE-2025-66407` is an authenticated SSRF pattern in Weblate's component creation flow:

- the user-controlled repository URL was not sanitized for arbitrary schemes, hosts, or local paths;
- when the Mercurial backend handled the URL, Weblate exposed the full server-side HTTP response;
- `file://` targets produced useful existence-oracle behavior for local file enumeration.

Fixed version: Weblate `5.15`.

This is useful beyond the single advisory because many VCS-backed importers and "create component" wizards reuse the same risky shape: a trusted backend fetcher, a user-supplied repository URL, and a validation layer that checks the wrong backend or only the happy path.

## Why operators care

For authorized testing, this can expose:

- internal HTTP endpoints reachable only from the Weblate host;
- response bodies from non-public services;
- local file existence or path layout;
- backend-specific behavior differences between Git and Mercurial.

That makes it a good recon and exploit-path discovery target, not just a product-specific CVE.

## Triage

1. Find component-creation, import, or repository-connection flows that accept a URL.
2. Confirm whether the product supports more than one VCS backend.
3. Check whether validation happens before the VCS backend is selected or only for one backend.
4. Look for `file://`, localhost, loopback, RFC1918, metadata-style, or redirect-capable URLs in repository fields.
5. Verify whether the response is blind, semi-blind, or body-exposing.

## Safe validation workflow

Use only owned lab services or approved canaries.

1. Point the repository URL at a callback host you control.
2. Use a unique path per attempt and log source IP, headers, and response size.
3. Repeat with a benign local-file target in a lab environment if file enumeration is in scope.
4. Compare the Mercurial path against the Git path to see whether the bug is backend-specific.

A strong proof shows both the attacker-controlled input and the backend-observed fetch.

## Bypass variants worth checking

- scheme changes after normalization
- redirects from an allowed host to a blocked destination
- mixed-case or encoded URL schemes
- `localhost`, `127.0.0.1`, `::1`, and IPv4-mapped IPv6 forms
- `file://` and other non-HTTP schemes
- userinfo tricks such as `allowed.example@evil.example`
- backend mismatch: UI validates one VCS, fetcher uses another

## Reporting heuristic

Include:

- the exact role required to create or edit the repository/component
- the backend selected at fetch time
- the repository URL field and any related import/base URL fields
- callback evidence or file-oracle evidence
- whether the response is blind or body-exposing
- the lowest-risk internal target or local-file proof allowed by scope
- the version and backend matrix that reproduces the issue

## Durable lesson

Repository URL validation has to happen at the fetch boundary, not just at the form boundary. If a platform supports multiple VCS backends, each backend needs its own URL policy, canonicalization rules, and scheme allowlist.

## Sources

- [GitHub Advisory Database: GHSA-hfpv-mc5v-p9mm](https://github.com/advisories/GHSA-hfpv-mc5v-p9mm)
- [GitHub Advisory Database: Weblate advisories](https://github.com/WeblateOrg/weblate/security/advisories)
