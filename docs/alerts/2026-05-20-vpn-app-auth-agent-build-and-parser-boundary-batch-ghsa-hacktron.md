# VPN, app-auth, agent-build, and parser-boundary batch

Sources: GitHub Security Advisories REST fallback, updated 2026-05-20; Hacktron AI Research, published 2026-05-20: [When Your VPN Opens Your Private Network to the Public](https://www.hacktron.ai/blog/cve-2026-0265-panos-globalprotect-cas-auth-bypass).

This batch is durable because the individual bugs share reusable failure modes: identity proofs accepted without binding them to the expected algorithm or tenant, administrative APIs trusting caller-supplied object IDs and mass-assigned fields, developer tools executing repository-controlled configuration in privileged contexts, and parsers or dev helper servers crossing resource and network boundaries.

## What changed

- **Palo Alto PAN-OS GlobalProtect CAS auth bypass (CVE-2026-0265):** Hacktron described a Cloud Authentication Service JWT verification flaw where the firewall accepted the token `alg` from attacker-controlled JWT headers. Switching from RS256 to HS256 caused certificate bytes to be used as an HMAC secret, enabling authentication bypass for CAS-backed GlobalProtect flows when an attacker could construct the required token material.
- **phpMyFAQ account and API control-plane bugs:** GitHub advisories `GHSA-w9xh-5f39-vq89`, `GHSA-gp95-j463-vv28`, `GHSA-xvp4-phqj-cjr3`, and `GHSA-9qv9-8xv6-5p35` describe missing password-reset token validation, empty default API token acceptance, and IDOR-style password overwrite paths affecting phpMyFAQ before 4.1.3.
- **Flowise and wger tenant-boundary issues:** `GHSA-c2c9-mfw7-p8hw`, `GHSA-59fh-9f3p-7m39`, and `GHSA-m837-xvxr-vqwg` cover Flowise cross-workspace chatflow disclosure, user-field mass assignment, and a hardcoded wildcard CORS TTS endpoint. `GHSA-mw8f-w6p8-xrf4` covers wger cross-tenant account activation/deactivation/deletion when gym scoping collapses around `None`.
- **Developer/build trust bugs:** `GHSA-pqwm-q9pv-ph8r` and `GHSA-5wxr-w449-57cm` cover `shivammathur/setup-php` command-injection/token-exposure paths. `GHSA-7wx4-6vff-v64p` covers Diffusers `trust_remote_code` TOCTOU bypass. `GHSA-fvvm-949w-qj4w` covers RTK silently trusting project-local output filters that can tamper with command output shown to an LLM.
- **Supply-chain compromise:** `GHSA-pvw4-cvr4-97p8` covers malicious `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, and `@cap-js/db-service@2.10.1` releases that harvested credentials and attempted self-propagation.
- **Parser, render, and dev-helper exposure:** `GHSA-q23m-vm9r-5745` covers podinfo reflected XSS via content sniffing on echo endpoints; `GHSA-337m-mw94-2v6g` covers Apache Commons Configuration YAML cycle recursion; `GHSA-468c-vq7p-gh64` covers Plug multipart header buffer exhaustion; `GHSA-pxh5-6rrc-8rjv` covers OpenTofu `init` resource exhaustion from attacker-controlled registries; `GHSA-hw27-4v2q-5qff` and `GHSA-gj84-924c-48fx` cover Algernon auto-refresh SSE CORS and all-interface bind defaults.

## Operator triage

1. **Patch exposed identity surfaces first.** Prioritize PAN-OS GlobalProtect/CAS deployments, phpMyFAQ, Flowise, wger, public podinfo demos, and any internet-exposed dev helpers.
2. **Treat algorithm fields as untrusted claims.** JWT verification must bind accepted algorithms to key type, issuer policy, and configured identity-provider metadata; never dispatch verifier choice solely from token header input.
3. **Audit password-reset and admin APIs.** Require single-use reset tokens, old-password or step-up checks for credential changes, authorization checks on target user IDs, and rate limits/enumeration-resistant responses.
4. **Harden tenant selectors.** Make `NULL`/unset tenant values fail closed, and add negative tests for “both sides unset” comparisons across authorization helpers.
5. **Rotate after malicious package exposure.** If the affected `@cap-js/*` versions were ever installed, treat npm tokens, GitHub PATs, SSH keys, cloud credentials, and CI secrets on that host/runner as compromised.
6. **Constrain developer automation.** Pin patched `setup-php`, avoid trusted-context workflows on attacker-controlled repository files, disable unreviewed project-local LLM output filters, and require explicit trust for model/repository code loading.
7. **Limit parser and helper-service blast radius.** Add body/header byte ceilings, recursion limits, loopback-only defaults, explicit CORS allowlists, `Content-Type`, and `X-Content-Type-Options: nosniff` on endpoints that reflect request content.

## Replayable validation boundaries

- **JWT algorithm-confusion test:** present a lab JWT whose header swaps an asymmetric algorithm for an HMAC algorithm while reusing public certificate bytes; expected result is hard rejection before signature verification.
- **Password-reset invariant test:** attempt reset/update flows with only username/email or caller-supplied user IDs; expected result is no state change without a valid single-use token and target-specific authorization.
- **Tenant-null test:** create two users/resources with unset tenant/gym/workspace fields and attempt cross-object operations; expected result is deny-by-default, not equality success.
- **Workflow config injection test:** run CI on a pull request that modifies `.php-version`, `composer.json`, `composer.lock`, model index files, or local LLM-filter config; expected result is no privileged command execution and visible trust prompts.
- **Parser/resource test:** send cyclic YAML, oversized multipart part headers, malicious registry responses, and reflected HTML bodies to staging services; expected result is bounded memory/CPU and safe content typing.
- **Dev-helper network test:** scan developer machines and containers for Algernon-style helper ports bound to non-loopback interfaces; expected result is loopback-only or authenticated access.

## Durable controls

- Authenticate *state transitions*, not just endpoints. Credential changes, account activation, API-token use, and tenant reads need explicit target authorization and audit trails.
- Normalize identity inputs into policy objects before verification. JWT `alg`, issuer, audience, key ID, key type, and tenant binding should be validated together.
- Treat repository, model, and project-local configuration as attacker-controlled unless the current trust decision says otherwise.
- Put byte, recursion, and wall-clock ceilings on every untrusted parser path; test malformed inputs in CI, not only happy-path examples.
- Use loopback-safe defaults for developer convenience services. If a helper must bind externally, require authentication, explicit operator opt-in, and clear startup logs.
