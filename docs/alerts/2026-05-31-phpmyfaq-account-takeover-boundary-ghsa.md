# phpMyFAQ password-reset and admin IDOR account-takeover boundaries

Sources: [GHSA-w9xh-5f39-vq89](https://github.com/advisories/GHSA-w9xh-5f39-vq89), [upstream advisory GHSA-w9xh-5f39-vq89](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-w9xh-5f39-vq89), [GHSA-xvp4-phqj-cjr3](https://github.com/advisories/GHSA-xvp4-phqj-cjr3), and [upstream advisory GHSA-xvp4-phqj-cjr3](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-xvp4-phqj-cjr3), updated on 2026-05-31.

These phpMyFAQ issues are useful beyond one product because they expose two common bug-hunting seams: password-reset endpoints that trust username/email pairs without a reset token, and privileged admin APIs that accept a target `userId` without checking whether the caller may modify that account. Treat this as an authorized validation checklist for helpdesk, FAQ, knowledge-base, and admin-console assessments.

## Advisory signals

- **Unauthenticated password reset without token** — phpMyFAQ `< 4.1.3` exposes `PUT /api/user/password/update` with only `username` and `email` in the JSON body. When the pair is valid, the server changes the account password and emails the new plaintext password without requiring a time-limited reset token, prior confirmation, or rate limiting.
- **Username/email enumeration oracle** — mismatched input can distinguish “user does not exist” from “email does not exist,” giving testers a low-noise way to confirm candidate accounts before attempting an authorized reset workflow.
- **Admin password-overwrite IDOR** — `PUT /admin/api/user/overwrite-password` checks for `USER_EDIT` and CSRF but trusts request-body `userId`. A lower-privileged admin can target SuperAdmin `userId=1` or another administrator if role/ownership checks are absent.
- **Shared boundary** — both flaws turn identity metadata or object IDs into authorization decisions. The replayable lesson is to test every password-change path for a binding between requester, reset token or CSRF token, target account, privilege tier, and intended action.

## Operator triage

1. Confirm the in-scope product and version. Prioritize phpMyFAQ instances below `4.1.3`, internet-facing knowledge bases, support portals, and internal FAQ portals with separate admin roles.
2. Map the password lifecycle endpoints: forgot-password request, reset-token verification, direct password update APIs, admin password overwrite APIs, and any mobile/API routes not exposed in the normal UI.
3. For unauthenticated reset testing, use lab accounts or explicit written permission. Send a benign request with an invalid email for a known test username and compare it with an unknown username. The useful proof is the response differential and missing token requirement, not taking over a real user.
4. For token-boundary validation, attempt the same reset update without a reset token, with an expired token, with a token issued for a different account, and with only username/email metadata. Expected safe behavior: all fail before any password change or email delivery.
5. For admin IDOR validation, create two admin-tier test accounts with different roles. Capture a legitimate CSRF token for the lower-privileged admin, then change only the `userId` to a higher-privileged test account. Expected safe behavior: the server rejects the request based on target-account privilege/ownership, not just CSRF validity.
6. Check logs and mail side effects. A safe fix should avoid plaintext password delivery, avoid user enumeration messages, throttle attempts, and emit auditable failed authorization events.

## Safe validation boundaries

- Do not reset production admin passwords unless the scope explicitly authorizes that impact and the account owner is coordinated. Prefer disposable accounts and staging clones.
- Treat email delivery as an impact boundary: triggering reset mail to a real user can be disruptive even if the tester never receives the password.
- Avoid brute-force enumeration. A small, documented matrix of known test accounts is enough to prove the missing-token or response-oracle behavior.
- Do not publish real usernames, email addresses, CSRF tokens, session cookies, or generated passwords. Redact identifiers in screenshots and request logs.

## Reporting heuristics

- Separate the two findings if both exist: unauthenticated tokenless reset is a pre-auth account-takeover path; admin overwrite IDOR is an authenticated privilege-escalation path.
- Show the exact authorization value that is missing: reset token, token-to-account binding, caller-to-target authorization, target privilege comparison, or rate-limit/user-enumeration control.
- Include a minimal request/response pair using lab accounts and state whether a password was changed, an email was sent, or the target account became usable.
- Recommend regression tests that bind reset tokens to account, purpose, expiration, and one-time use, and bind admin password changes to caller permissions plus target-account privilege/ownership.
