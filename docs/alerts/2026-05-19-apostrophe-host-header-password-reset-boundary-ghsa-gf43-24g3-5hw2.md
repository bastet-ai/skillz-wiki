# Apostrophe host-header password-reset boundary

Source: [GHSA-gf43-24g3-5hw2](https://github.com/advisories/GHSA-gf43-24g3-5hw2), updated 2026-05-19.

This is durable because the exploit is not an Apostrophe-only quirk: any password-reset, invite, magic-link, email-verification, or OAuth callback flow that builds absolute URLs from `Host`/`X-Forwarded-*` request metadata can turn a legitimate email into token exfiltration. In ApostropheCMS, `passwordReset: true` plus an unset `apos.baseUrl` made the reset route derive the emailed link from attacker-controlled `req.hostname`.

## What changed

- `apostrophe <= 4.29.0` could send password-reset links for a real user to an attacker-controlled hostname when `apos.baseUrl` was not configured.
- The reset token was valid; the weakness was the trust boundary around absolute URL construction.
- Exploitation required a known user email and victim click, but no attacker authentication.
- GitHub lists no patched version at the time of this scan; the immediate operator control is explicit canonical-origin configuration.

## Operator triage

1. Search Apostrophe deployments for enabled password reset without a canonical base URL:

```js
modules: {
  '@apostrophecms/login': { options: { passwordReset: true } },
  '@apostrophecms/express': { options: { baseUrl: 'https://example.com' } }
}
```

2. If `passwordReset: true` is set and `baseUrl` is absent, add the production origin before allowing reset requests on the public edge.
3. Review web/proxy logs for reset requests where `Host` differs from the site origin, especially `POST /api/v1/login/reset-request` with known staff or admin email addresses.
4. Treat recent reset clicks as potentially compromised if the emailed URL used an unexpected host; invalidate active sessions and rotate credentials for affected accounts.
5. Add regression coverage that sends a reset request with a hostile `Host` header and asserts the emailed link still uses the configured canonical origin.

## September 18 follow-up: the same class via the `Origin` header (SOGo)

**SOGo before 5.12.11** [GHSA-gqgv-6fx9-g8mx / CVE-2026-93453](https://github.com/advisories/GHSA-gqgv-6fx9-g8mx) shows the request-derived-authority bug through a different header: the groupware constructs **password-reset links using the client-supplied `Origin` header as the URL authority**. An unauthenticated attacker submits a recovery request for a victim address with `Origin: https://attacker.example`, and the valid reset token is mailed to the victim's recovery address *inside a link pointing at attacker infrastructure* — the victim's own click delivers the token. Account takeover without touching the mail path.

Operator extension of the triage above: probe **both** `Host` and `Origin` (and both absent) on every recovery/invite/verification flow — header → emitted-link-authority decision tables routinely show one header honored and the other not, and fixing only `Host` regressions leaves the `Origin` leg open (SOGo's fix shipped in 5.12.11). On authorized targets only, use a lab address with an owned recovery mailbox and redact tokens from all evidence.

## Durable controls

- Do not derive security links from inbound request hostnames. Use a configured canonical origin for reset, invite, verification, unsubscribe, webhook callback, and OAuth redirect URLs.
- At the reverse proxy, reject unknown `Host` values before the application sees them; do not rely on framework URL helpers to enforce origin policy.
- Keep token-bearing links single-use, short-lived, and bound to the account/action they were issued for, but remember that token hygiene does not fix host-header exfiltration by itself.
- Include host-header injection tests in auth-flow checklists: reset emails, magic links, SSO links, tenant invites, admin approval links, and API-key enrollment links.
- Log the origin used for generated security emails so incident review can distinguish normal resets from poisoned-link attempts.
