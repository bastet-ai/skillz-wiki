# Web Application Security Checklist

Use this as a compact pre-report pass after you finish primary testing.

## Surface mapping

- [ ] Hostnames, ports, and entry points are enumerated
- [ ] Login, registration, password reset, and invite flows are identified
- [ ] Admin or support-only surfaces are mapped
- [ ] API endpoints are captured separately from browser pages

## Authentication and session handling

- [ ] Authentication methods are documented
- [ ] Session cookies and token storage locations are identified
- [ ] Logout and session invalidation behavior is verified
- [ ] MFA, password reset, and recovery paths are tested

## Authorization and access control

- [ ] Horizontal access control was tested across at least two identities
- [ ] Vertical access control was tested across privilege boundaries
- [ ] Direct object references were tested for predictable resources
- [ ] Server-side enforcement was checked independently of the UI

## Input handling

- [ ] Reflected and stored input was tested in every major sink
- [ ] File upload validation was tested for type, size, and content handling
- [ ] Server-side template or command execution paths were considered
- [ ] Error messages were reviewed for stack traces, secrets, or internal paths

## Application logic

- [ ] Multi-step flows were tested for skipped or reordered steps
- [ ] Pricing, discount, quota, or credit logic was challenged
- [ ] Race conditions were considered for high-value actions
- [ ] Unsafe default states were tested after object creation

## Infrastructure and integrations

- [ ] Common headers, TLS posture, and caching behavior were checked
- [ ] Third-party integrations and webhooks were mapped
- [ ] Secrets or tokens were not exposed to the client unintentionally
- [ ] Debug or staging features were not reachable from production paths

## Reporting gate

- [ ] Evidence is attached for every confirmed issue
- [ ] Reproduction steps are minimal and deterministic
- [ ] Impact statements match what was actually observed
