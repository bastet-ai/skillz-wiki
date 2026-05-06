# Webhook, tenant, and token-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-06** batch where webhook authenticity, tenant scoping, catalog reads, and token validation crossed trust boundaries.

## Advisories covered

- **Axonflow SDK webhook verification gap** — [GHSA-mhc4-qq83-fmrr](https://github.com/advisories/GHSA-mhc4-qq83-fmrr), [GHSA-7f4h-6264-89fr](https://github.com/advisories/GHSA-7f4h-6264-89fr): Go and Python SDK types did not expose the HMAC-SHA256 signing key needed for consumers to verify webhook signatures.
- **Axonflow multi-tenant isolation and access-control hardening** — [GHSA-9h64-2846-7x7f](https://github.com/advisories/GHSA-9h64-2846-7x7f): tenant isolation bugs were fixed as an authorization boundary, not only as application logic.
- **Backstage catalog cross-owner reads** — [GHSA-p7g9-rp3g-mgfg](https://github.com/advisories/GHSA-p7g9-rp3g-mgfg): authenticated users could read unprocessed catalog data across owners when permission checks were missing.
- **OpenTelemetry Collector contrib Azure auth extension bearer replay** — [GHSA-pjv4-3c63-699f](https://github.com/advisories/GHSA-pjv4-3c63-699f): `Authenticate` accepted replayed bearer tokens without adequate validation.
- **fast-jwt empty-HMAC-secret auth bypass** — [GHSA-gmvf-9v4p-v8jc](https://github.com/advisories/GHSA-gmvf-9v4p-v8jc): async key resolution could accept an empty HMAC secret.
- **Lemmy private community data exposure** — [GHSA-95q8-x6r6-672m](https://github.com/advisories/GHSA-95q8-x6r6-672m): community, saved, liked, and modlog API views could expose private-community data.
- **OpenClaw pairing and Matrix reply-context allowlist issues** — [GHSA-gg9v-mgcp-v6m7](https://github.com/advisories/GHSA-gg9v-mgcp-v6m7), [GHSA-rg8m-3943-vm6q](https://github.com/advisories/GHSA-rg8m-3943-vm6q): bootstrap codes and threaded context need explicit sender, channel, and session binding.

Withdrawn duplicate OpenClaw advisories in this scan were treated as duplicate metadata only and should not create new operational guidance unless the canonical advisory changes.

## Why this is durable

Webhook verification, tenant ownership, and token validation are the same control: bind the message or object to the principal that is allowed to act on it. SDK ergonomics that make verification impossible are security bugs even when the server signs correctly.

## Immediate triage

1. Patch affected packages and services; prioritize webhook consumers, multi-tenant developer portals, and token-authenticated control planes.
2. Confirm webhook handlers reject missing signatures, unknown keys, stale timestamps, and replayed delivery IDs.
3. Add owner/tenant checks inside catalog/query helpers, not only at HTTP route boundaries.
4. Reject empty, default, or unresolved JWT verification keys; fail closed when async key resolution errors.
5. Re-test thread/reply context allowlists with spoofed roots, replies, and bootstrap-code reuse.

## Durable controls

- Make signature-verification material part of the public SDK contract and test that consumers can verify every webhook.
- Treat unprocessed or internal catalog views as sensitive data requiring the same permissions as processed views.
- Bind bearer tokens to issuer, audience, tenant, token family, expiry, and replay protections before accepting them.
- Scope setup codes and threaded message context to one principal, one channel, one purpose, and a short lifetime.
