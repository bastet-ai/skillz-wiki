# NetLicensing MCP and nebula-mesh control-plane boundary checks

Source: hourly offensive-security scan, 2026-07-14 late GitHub advisory wave. Primary entries: [GHSA-x9vc-9ffq-p3gj](https://github.com/advisories/GHSA-x9vc-9ffq-p3gj) / CVE-2026-54446, [GHSA-7rx3-5wx3-5v76](https://github.com/advisories/GHSA-7rx3-5wx3-5v76), [GHSA-cm26-5974-52h8](https://github.com/advisories/GHSA-cm26-5974-52h8) / CVE-2026-61699, and [GHSA-g4x6-jcvr-9m3g](https://github.com/advisories/GHSA-g4x6-jcvr-9m3g) / CVE-2026-55513.

This batch is durable because each advisory maps to a repeatable operator boundary: an MCP HTTP transport that silently falls back to the server operator's upstream API key when the caller supplies no key, a mesh webhook feature where non-admin operators can opt out of SSRF guards, a certificate-revocation workflow that updates control-plane state but never reaches the data plane, and a Web UI host-creation path that mints longer-lived bearer enrollment tokens than the configured policy.

!!! warning "Authorized validation only"
    Keep proofs to disposable NetLicensing-MCP and nebula-mesh labs, fake NetLicensing accounts or mocked upstream APIs, owned webhook callback hosts, loopback-only internal canaries, synthetic mesh hosts, short-lived test enrollment tokens, and inert route/status markers. Do not call production licensing APIs, create/delete real customer licenses, fetch cloud metadata, probe production internal services, capture real mesh traffic, reuse production certificates, enroll unauthorized devices, or publish bearer tokens/API keys.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-x9vc-9ffq-p3gj](https://github.com/advisories/GHSA-x9vc-9ffq-p3gj) / CVE-2026-54446 | `netlicensing-mcp` HTTP transport | Missing client API key is forwarded downstream, where the client falls back to `NETLICENSING_API_KEY` from the server environment | Add unauthenticated MCP HTTP tool-invocation checks for server-side credential fallback. |
| [GHSA-7rx3-5wx3-5v76](https://github.com/advisories/GHSA-7rx3-5wx3-5v76) | nebula-mesh managed webhooks | Non-admin operators can set `allow_private: true`, causing the dispatcher to use an unguarded HTTP client for webhook delivery | Test low-privilege webhook configuration for SSRF guard opt-out fields. |
| [GHSA-cm26-5974-52h8](https://github.com/advisories/GHSA-cm26-5974-52h8) / CVE-2026-61699 | nebula-mesh host revocation | The control plane sends blocklist updates, but the agent discards them and generated configs omit `pki.blocklist` | Validate that revocation state changes are enforced by mesh peers, not just shown in the UI/API. |
| [GHSA-g4x6-jcvr-9m3g](https://github.com/advisories/GHSA-g4x6-jcvr-9m3g) / CVE-2026-55513 | nebula-mesh Web UI host creation | `POST /ui/hosts` hardcodes roughly 24-hour enrollment-token expiry instead of using configured TTL policy | Add UI-vs-API token-lifetime parity checks to mesh enrollment workflows. |

## Replayable validation boundaries

### NetLicensing-MCP server-side API key fallback

1. Start `netlicensing-mcp` in HTTP transport mode in a lab with `NETLICENSING_API_KEY` set to a fake key accepted by a mocked NetLicensing upstream, or to a low-risk test account explicitly approved for the assessment.
2. Send a normal MCP request with a caller-supplied `x-netlicensing-api-key` and confirm the upstream sees the caller key.
3. Repeat with no `x-netlicensing-api-key` header and no `?apikey=` query parameter.
4. Invoke only harmless read/list tools first, then marker-only create/update/delete tools against disposable products or mock resources if those operations are in scope.
5. Record whether the unauthenticated request is accepted and whether the upstream receives the server environment key.
6. Add controls for a patched build, missing server key, invalid caller key, network-level authentication in front of HTTP mode, and stdio mode.

Report this as **unauthenticated MCP HTTP caller -> missing per-request key enforcement -> upstream API request under server operator credential**. Evidence should be method/tool name, auth state, mocked upstream key class, and marker object ID; redact all key material.

### nebula-mesh webhook `allow_private` SSRF guard bypass

1. Create a nebula-mesh lab with one admin, one non-admin operator, one owned callback host, and one loopback or RFC1918 canary listener under your control.
2. As the non-admin operator, create a webhook subscription first with `allow_private: false` and a private canary URL; record the expected rejection or guarded-delivery failure.
3. Repeat with the same target and `allow_private: true` using only a harmless event such as a synthetic host-enrollment marker.
4. Verify whether the server dispatches to the private canary despite the role being non-admin.
5. Add controls for admin behavior, patched role-gated `allow_private`, public callback URLs, update-vs-create paths, and disabled webhook subscriptions.

Report this as **low-privilege webhook config -> guard opt-out flag -> server-side request to private address class**. Do not target metadata services, cluster APIs, Unix sockets, production admin panels, or third-party hosts.

### nebula-mesh revocation data-plane enforcement gap

1. Build a lab mesh with a dedicated CA and two synthetic hosts: Host A as an allowed peer and Host B as the revocation target.
2. Confirm baseline Host A <-> Host B connectivity with only marker traffic.
3. Revoke or block Host B through the UI/API and wait for Host A's agent update poll to complete.
4. Inspect only lab-generated config/state to determine whether `pki.blocklist` or equivalent revocation material reaches Host A's Nebula daemon.
5. Attempt the same marker connection from Host B and record whether the handshake still succeeds until certificate expiry.
6. Add controls for newly generated configs, manually injected blocklists, patched agents, expired certificates, and a host under a different CA.

Report this as **control-plane host block -> blocklist not applied by agents/config generator -> revoked certificate still accepted by peers**. Keep evidence to host IDs, fingerprint prefixes, config key presence/absence, and marker connectivity; never capture production traffic or private keys.

### nebula-mesh Web UI enrollment-token TTL drift

1. Configure a lab server and network with a deliberately short enrollment-token TTL, such as five minutes, and verify the API host-creation path uses that TTL.
2. As an authenticated operator who can create hosts, create an equivalent host through `POST /ui/hosts`.
3. Compare the returned or stored `expires_at` for UI-created and API-created enrollment tokens.
4. Attempt enrollment only for synthetic pending hosts and stop after proving whether the longer-lived UI token is accepted beyond the configured short TTL window.
5. Add controls for patched UI behavior, token-regeneration routes, admin vs non-admin operators, and networks without TTL overrides.

Report this as **Web UI host creation -> hardcoded bearer enrollment-token expiry -> token lifetime exceeds policy**. Redact token values; use only disposable hosts and do not enroll real devices.

## Reporting notes

- Lead with preconditions: MCP transport mode and exposure, whether a server-side upstream API key is configured, nebula-mesh operator role, webhook event reachability, configured private-address guard policy, revocation polling cadence, certificate lifetime, and configured enrollment-token TTL.
- Prefer decision tables over payload dumps: caller role, supplied header/query/body field, expected guard or token policy, observed route/tool dispatch, marker callback or mesh effect, and patched negative control.
- Redact API keys, bearer tokens, enrollment tokens, certificate fingerprints beyond short prefixes, hostnames from customer environments, callback tokens, upstream account IDs, and mesh config containing private keys.
- Adjacent nebula-mesh plaintext-token and OIDC state-allocation advisories in the same wave were marked processed without promotion because this run did not identify a safe offensive workflow beyond existing secret-storage and DoS-exclusion guidance.
