# OmniFaces CDNResourceHandler wildcard mapping EL injection (GHSA-vp6r-9m58-5xv8 / CVE-2026-41883)

**Signal:** GitHub Security Advisories updated **2026-04-30**. OmniFaces fixed server-side Expression Language evaluation through crafted resource names when `CDNResourceHandler` used wildcard CDN mappings.

## What it is
Applications using OmniFaces `CDNResourceHandler` with wildcard mappings such as `libraryName:*=https://cdn.example.com/*` could allow an attacker to place an EL expression inside a resource request name. The vulnerable handler evaluated the crafted resource name server-side. Impact depends on the JSF/EL implementation and exposed context objects, but can range from information disclosure and denial of service to remote code execution.

Applications using only explicit resource-to-URL CDN mappings are not affected by this specific wildcard path.

Affected Maven package: `org.omnifaces:omnifaces` before `1.14.2`, `2.7.32`, `3.14.16`, `4.7.5`, or `5.2.3` depending on branch.

Reference: <https://github.com/advisories/GHSA-vp6r-9m58-5xv8>

## Triage
1. Find JSF applications using OmniFaces and `CDNResourceHandler`.
2. Search configuration for wildcard CDN resource mappings (`*`) rather than explicit resource names.
3. Review access logs for resource requests containing `${`, `#{`, URL-encoded braces, EL operators, long arithmetic expressions, or unexpected library/resource names.
4. Treat successful probes against authenticated admin sessions as potential account or server compromise if the EL context exposed dangerous objects.

## Mitigation
- Upgrade OmniFaces to the fixed release for the deployed branch.
- Replace wildcard CDN mappings with explicit resource-to-URL mappings.
- Restrict CDN resource handling to known static assets and reject resource names containing EL metacharacters before handler dispatch.
- Keep JSF/EL runtime hardening in place so template/resource paths cannot reach command, reflection, classloader, or filesystem primitives.

## Detection ideas
- Alert on resource URLs containing encoded or raw `#{...}` / `${...}` syntax.
- Monitor CDN fallback and JSF resource-handler errors for suspicious library names.
- Review WAF logs for EL-injection payloads against `/javax.faces.resource/` and OmniFaces resource paths.

## Durable lesson
Wildcard static-resource mapping is executable-input handling when the framework performs expression resolution. Static asset routers must reject template syntax before any path is interpreted by server-side view technology.
