# Web app SSRF, auth, and state-boundary batch (GHSA)

**Signal:** GitHub Security Advisories Atom/REST surfaced a **2026-05-04** batch where web applications and registries crossed XML, SSRF, session, authorization, and destructive-state boundaries.

## Advisories in this batch

- **changedetection.io XXE** — `changedetection.io <= 0.54.9` accepted XML in a way that could trigger external entity processing. References: <https://github.com/advisories/GHSA-v7cp-2cx9-x793>, CVE-2026-41895.
- **Signal K Server WebSocket login brute force** — `signalk-server <= 2.24.0` lacked rate limiting on the WebSocket login endpoint. References: <https://github.com/advisories/GHSA-vmfm-ch9h-5c7g>, CVE-2026-41893.
- **CI4MS deactivated-user session bypass** — `ci4-cms-erp/ci4ms >= 0.26.0, <= 0.31.7.0` allowed sessions for users marked inactive. References: <https://github.com/advisories/GHSA-5hfv-c864-qcq9>, CVE-2026-41891.
- **CI4MS arbitrary table drop through theme deletion** — `ci4-cms-erp/ci4ms >= 0.31.1.0, <= 0.31.7.0` allowed destructive database table deletion via `Theme deleteProcess`. References: <https://github.com/advisories/GHSA-vgrf-pr28-vf98>, CVE-2026-41890.
- **Distribution tag deletion policy bypass** — `github.com/distribution/distribution/v3 < 3.1.1` and legacy `github.com/distribution/distribution <= 2.8.3` could delete tags despite `storage.delete.enabled` being disabled. References: <https://github.com/advisories/GHSA-6pjf-3r9x-m592>, CVE-2026-41888.
- **nova-toggle-5 boolean field authorization bypass** — `almirhodzic/nova-toggle-5 < 1.3.0` let non-Nova users modify boolean fields through the toggle endpoint. References: <https://github.com/advisories/GHSA-f5c8-m5vw-rmgq>, CVE-2026-42202.
- **RedwoodSDK same-site CSRF** — `rwsdk >= 1.0.0-beta.50, <= 1.2.2` lacked origin validation for server actions. References: <https://github.com/advisories/GHSA-m2m6-cff5-3w7c>, CVE-2026-42190.
- **Lemmy post-link metadata SSRF** — `lemmy_api_common < 0.19.18` could fetch internal images through unvalidated `og:image` metadata. References: <https://github.com/advisories/GHSA-h6hf-9846-xwrq>, CVE-2026-42181.
- **Lemmy Webmention SSRF** — `lemmy_api_common < 0.19.18` could trigger SSRF via `/api/v3/post` Webmention dispatch. References: <https://github.com/advisories/GHSA-3jvj-v6w2-h948>, CVE-2026-42180.

## Why this is durable

The batch is about server-side convenience features performing actions for the attacker: XML parsers fetch entities, previewers fetch metadata, Webmention dispatchers call remote URLs, session middleware trusts stale user state, toggles mutate model fields, and registry APIs delete data despite policy flags.

## Immediate triage

1. **Patch affected web apps and libraries** or remove internet exposure until fixed.
2. **Disable risky helpers:** XML import, URL preview, Webmention, server actions, Nova toggle endpoints, and registry tag deletion where they are not required.
3. **Add compensating controls:** WAF/rate limits for WebSocket login, egress allowlists for preview/Webmention workers, and CSRF origin checks for same-site actions.
4. **Revalidate sessions:** force logout for deactivated CI4MS users and check whether inactive accounts retained valid cookies.
5. **Verify data integrity:** inspect registry tag deletion logs and CI4MS database metadata for unexpected destructive operations.

## Hunt ideas

- Search changedetection.io logs for XML documents containing `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `file://`, or cloud metadata URLs.
- Query outbound proxy logs for Lemmy requests to RFC1918, link-local, loopback, metadata, or internal service hostnames.
- Review Signal K WebSocket login failures by username/IP and add lockout telemetry.
- Inspect CI4MS sessions where `active=0`, theme deletion requests, and `DROP TABLE` activity near web requests.
- Compare registry tag delete events against `storage.delete.enabled=false` deployments.
- Check RedwoodSDK server-action POSTs with missing or unexpected `Origin`/`Sec-Fetch-Site` headers.

## Durable controls

- Disable external entity resolution and network/file access in XML parsers by default.
- Run URL preview and Webmention fetches in isolated workers with strict egress policy and response-size limits.
- Recheck account state on every privileged request, not only at login.
- Require per-field authorization for generic toggle endpoints.
- Treat “delete disabled” flags as enforcement points that tests must cover, not documentation hints.
- Require Origin/Fetch Metadata validation on same-site server actions.

## Operator lesson

Any web feature that “helps” by fetching, rendering, toggling, or deleting needs its own boundary. Convenience endpoints are high-value because they often skip the boring checks that core routes already have.
