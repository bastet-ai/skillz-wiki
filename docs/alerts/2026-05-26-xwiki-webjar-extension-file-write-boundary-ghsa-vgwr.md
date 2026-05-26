# XWiki WebJar extension file-write boundary (GHSA-vgwr-23fq-pr7g, 2026-05-26)

**Signal:** GitHub published `GHSA-vgwr-23fq-pr7g` / `CVE-2026-48047` for XWiki Platform's WebJars export path. A malicious WebJar extension installed from a configured extension repository could copy resources outside the intended export directory through path traversal. The advisory notes that an attacker first needs admin access on at least a subwiki and the ability to get a malicious extension into a configured repository, but the post-admin impact can include writing arbitrary files such as configuration files and setting the superadmin password.

The durable operator value is the chain shape: **low-scope wiki admin → extension install path → archive/resource traversal → host-level file write**.

## Why it matters for authorized testing

This is not an unauthenticated internet probe. It is useful during assessments where XWiki administration, tenant/subwiki boundaries, extension repositories, or post-compromise impact validation are in scope.

Reusable lessons:

1. **Subwiki admin is still a host-adjacent trust boundary.** A tenant or subwiki admin may be able to trigger platform code that writes under the shared XWiki filesystem.
2. **Extension repositories are code/data provenance boundaries.** If admins can add or install from attacker-controlled repositories, package resource paths become an attack surface.
3. **Resource-copy helpers need final canonical-path checks.** The patch added checks while copying resources from a JAR and while rewriting URLs inside CSS. Validate both file entries and embedded resource references.
4. **Post-admin impact should be proven safely.** A marker write inside a disposable lab export path is enough for most reports; do not overwrite configuration, passwords, or webroots on customer systems.

## Validation workflow

Only perform active validation in a lab or during an explicitly approved exploit-validation window.

### Recon

1. Fingerprint XWiki and collect the affected version range:
   - `org.xwiki.platform:xwiki-platform-webjars-api >= 9.6-rc-1, < 16.10.17`
   - `>= 17.0.0-rc-1, < 17.4.9`
   - `>= 17.5.0-rc-1, < 17.10.3`
2. Identify whether the test account has admin rights on the main wiki or only on a subwiki.
3. Enumerate configured extension repositories and whether a user with scoped admin rights can install a WebJar extension from them.
4. Confirm whether export/static-resource handling is enabled in the target environment and where exported resources land on disk.

### Safe proof shape

Use a disposable XWiki lab or customer-provided staging instance:

1. Build or obtain a benign WebJar-style extension whose resource name or CSS-referenced URL contains a traversal marker.
2. Configure a test extension repository that serves only the proof package.
3. Install it from a low-scope/subwiki admin account.
4. Trigger the resource-copy path.
5. Prove whether the copy attempts to escape the export root.

Keep evidence non-destructive:

- write only a random marker filename in a temporary owner-approved directory;
- never target `WEB-INF/xwiki.cfg`, `xwiki.properties`, password files, startup scripts, or webroots outside a dedicated lab;
- capture canonical source path, intended export root, attempted target path, status/error, and version.

The patch commit names the vulnerable helper as `FilesystemResourceReferenceCopier` and protects both direct JAR resource copies and URLs found in CSS. Use that as the regression-testing map.

## Variant checks

- JAR entries with `../`, encoded separators, leading slashes, Windows separators, or mixed normalization such as `a/..%2f..%2fmarker`.
- CSS `url(...)` references that resolve outside the copied resource directory.
- Extension packages installed from non-default repositories, private repositories, or proxy caches.
- Main-wiki admin versus subwiki admin behavior.
- Multi-tenant deployments where exported resources from one wiki share a filesystem root with another wiki.
- Differences between vulnerable file-read WebJar routes and file-write export/copy routes; do not assume one fix covers the other.

## Reporting heuristic

For a useful report, include:

- exact XWiki version and affected Maven package range;
- account role and wiki scope required to install the extension;
- configured repository provenance and whether a malicious package could be introduced;
- canonical export root and attempted escaped target path;
- whether CSS URL rewriting or direct JAR entry copying triggered the issue;
- safe proof marker and cleanup notes;
- why the finding is a tenant/admin-boundary escalation rather than a generic path traversal.

## Non-signal this hour

`GHSA-fgmm-w5cx-vrfw` / `CVE-2026-35202` for Pterodactyl is a Client API race that lets a user create more database allocations than assigned. It is a reasonable quota/TOCTOU test case, but this pass did not promote it because the advisory is low-severity, resource-limit oriented, and lacks a stronger exploit-path or reporting pattern beyond generic concurrent request testing.

## Sources

- [GitHub Advisory Database: XWiki WebJar extension file write (`GHSA-vgwr-23fq-pr7g`)](https://github.com/advisories/GHSA-vgwr-23fq-pr7g)
- [XWiki Platform advisory: potential arbitrary file writing using path traversal from WebJar](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-vgwr-23fq-pr7g)
- [XWiki Jira `XWIKI-23902`: Protect against path traversal from WebJar](https://jira.xwiki.org/browse/XWIKI-23902)
- [Patch commit `9f747fc`: protect against path traversal from WebJar](https://github.com/xwiki/xwiki-platform/commit/9f747fcd3200259a1de51957d3f5f6acc8e3816c)
