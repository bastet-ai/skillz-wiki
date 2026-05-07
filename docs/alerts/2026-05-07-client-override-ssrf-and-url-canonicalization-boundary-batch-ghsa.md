# Client override, SSRF, and URL-canonicalization boundary batch

**Sources:** GHSA-h4fw-6r7f-w494, GHSA-c2rm-g55x-8hr5 / CVE-2026-44589

## Why this matters

Two lower-severity advisories are durable because they show how security policy gets weakened when clients can steer server-side checks:

- `web-auth/webauthn-framework` Symfony bundle 5.3.0 allowed client overrides, including `userVerification: discouraged`, to downgrade a server-configured `userVerification: required`. 5.3.1 hardens the default.
- `nuxt-og-image` 6.2.5 through 6.4.8 left SSRF bypasses in the denylist added for a prior advisory, including IPv6-mapped loopback/private forms and redirect behavior. 6.4.9 patches the bypass.

The durable rule: policy inputs may be user-selected, but enforcement decisions need a server-owned final signal.

## Operator triage

1. Upgrade `web-auth/webauthn-framework` to 5.3.1+ and `nuxt-og-image` to 6.4.9+.
2. For WebAuthn flows, verify sensitive actions check the returned authenticator-data `UV` flag, not merely the requested options.
3. For OG/image fetchers, block loopback, RFC1918, link-local, unique-local, cloud metadata, and IPv4-mapped IPv6 after DNS resolution and after every redirect.
4. Disable redirect following for server-side image fetches unless each hop is revalidated.
5. Add tests for `::1`, `::ffff:127.0.0.1`, hex/decimal IPv4, private IPv6 ranges, DNS rebinding, and mixed-scheme redirects.

## Hunt prompts

- WebAuthn assertion or attestation option requests containing `userVerification: discouraged` when profile policy requires verification.
- Successful ceremonies for sensitive operations where `AuthenticatorData::isUserVerified()` is false.
- OG image generation requests targeting loopback/private/metadata hosts through IPv6 literals, mapped IPv4, redirects, or unusual URL encodings.
- Fetch logs where first-hop URL is public but redirect target is internal.

## Durable controls

- Treat client overrides as opt-in exceptions with explicit allowed values; default deny all security-sensitive overrides.
- Re-check the cryptographic/authenticator result, not just the request policy echoed through an options builder.
- Use a single canonical URL/IP policy engine for SSRF controls and apply it after DNS and each redirect.
- Prefer network egress deny rules around render/fetch workers so parser gaps do not expose internal services.
