# Identity, project, and registry-boundary batch

**Signal:** The **2026-05-08 18:15 UTC** advisory scan added a mixed application/control-plane batch: session revocation gaps, path-prefix containment mistakes, Kubernetes service-account token escalation, and MCP Registry SSRF/XSS issues.

## Advisories covered

- **Nhost sessions persist after password change/reset** — [GHSA-7hgr-xvrr-xpw3](https://github.com/advisories/GHSA-7hgr-xvrr-xpw3): `github.com/nhost/nhost` patched at pseudo-version `0.0.0-20260430132514-52c70664a7e9`.
- **potato-annotation string-prefix project-boundary bypass** — [GHSA-q9m2-fhv9-3jcf](https://github.com/advisories/GHSA-q9m2-fhv9-3jcf): `potato-annotation >= 2.0.0, < 2.4.5`; patch to `2.4.5+`.
- **ExternalSecrets service-account token secret overwrite/escalation** — [GHSA-fq7h-9x26-6j22](https://github.com/advisories/GHSA-fq7h-9x26-6j22): `github.com/external-secrets/external-secrets/apis >= 0.1.0, < 2.4.1`; patch to `2.4.1+`.
- **MCP Registry HTTP namespace verification SSRF via IPv6 6to4/NAT64/site-local gaps** — [GHSA-r48c-v28r-pf6v](https://github.com/advisories/GHSA-r48c-v28r-pf6v): `github.com/modelcontextprotocol/registry < 1.7.7`; patch to `1.7.7+`.
- **MCP Registry catalogue stored XSS via `websiteUrl` attribute quote breakout** — [GHSA-rqv2-m695-f8j4](https://github.com/advisories/GHSA-rqv2-m695-f8j4): `github.com/modelcontextprotocol/registry < 1.7.7`; patch to `1.7.7+`.

## Why this is durable

Each issue is a **boundary check that looked plausible but did not match the real security object**. Password changes updated credentials but not sessions. Path checks compared strings instead of path elements. Admission allowed a controller to mint service-account token secrets. SSRF defenses blocked common private ranges but missed IPv6 transition prefixes. HTML escaping handled text nodes, not attribute quotes.

## Immediate triage

1. Patch Nhost, potato-annotation, ExternalSecrets, and MCP Registry to the fixed versions above.
2. In Nhost deployments, revoke refresh tokens after password changes/resets and hunt for token use after recovery events.
3. Search project/path validation code for `startswith(real_base)`-style checks; replace with `commonpath`, `Path.is_relative_to`, or equivalent path-component-aware containment.
4. For ExternalSecrets, add admission policy blocking template creation of service-account-token/bootstrap-token secret types unless explicitly approved.
5. For MCP Registry or similar verification flows, test SSRF deny rules against IPv4-mapped IPv6, 6to4 `2002::/16`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, site-local `fec0::/10`, link-local, metadata, and DNS rebinding.
6. Review catalogue/UI fields rendered through `innerHTML` or template strings, especially URL attributes containing quotes.

## Durable controls

- Treat password change and reset as session lifecycle events: revoke or rotate refresh tokens, OAuth sessions, device tokens, and long-lived API tokens where appropriate.
- Do containment checks on canonical path objects plus separator-aware relative-path logic, never raw string prefixes.
- For Kubernetes controllers, deny dangerous generated Secret types at admission and scope controller permissions per namespace.
- Maintain SSRF blocklists as canonical IP classification libraries with transition-prefix coverage, DNS pinning, and connect-time IP enforcement.
- Escape by HTML context: text, attribute, URL, CSS, and JS sinks all require different encoders; avoid `innerHTML` for registry/catalogue data.
