# Keycloak and MLflow authentication-boundary batch

## Operator value

GitHub Advisory Database updates on 2026-06-04 exposed two durable offensive-testing themes for authorized identity and local-agent assessments:

- Keycloak OIDC, SAML, WebAuthn, and Admin API flaws cluster around session ownership, redirect canonicalization, client/audience binding, and token/action replay boundaries.
- MLflow Assistant's browser-reachable `/ajax-api` surface shows why loopback-only developer tools need origin and capability checks before local automation or agent execution is exposed.

Use these as replayable boundary checks, not generic version-alert content. A dependency match is only actionable when the affected feature, client configuration, or local assistant mode is reachable in scope.

## Affected surfaces

### Keycloak redirect URI wildcard and URI parser mismatch

- Advisory: [GHSA-rp95-xpg9-c2cq / CVE-2026-7504](https://github.com/advisories/GHSA-rp95-xpg9-c2cq)
- Product: `org.keycloak:keycloak-services`
- Affected versions: before `26.6.2`
- Required configuration: a client with wildcard entries in **Valid Redirect URIs**
- Boundary: Keycloak redirect validation must not disagree with Java URI parsing when a crafted authority/user-info section contains multiple `@` characters.

### Keycloak OIDC login-actions session fixation

- Advisory: [GHSA-hf67-5vvq-fm3r / CVE-2026-7507](https://github.com/advisories/GHSA-hf67-5vvq-fm3r)
- Product: `org.keycloak:keycloak-services`
- Affected versions: before `26.6.2`
- Required position: unauthenticated attacker who can pre-create an authentication session and induce a controlled user to visit a crafted link
- Boundary: `/login-actions/restart` must bind session handles to cookie ownership and CSRF context before resetting authentication-flow state.

### Keycloak disabled implicit-flow bypass via restart client data

- Advisory: [GHSA-hq3p-w4xv-x7vp / CVE-2026-7571](https://github.com/advisories/GHSA-hq3p-w4xv-x7vp)
- Product: `org.keycloak:keycloak-services`
- Affected versions: before `26.6.2`
- Required position: low-privilege user with valid credentials and knowledge of a target client ID
- Boundary: restart or resumed-session client data must not allow access-token delivery when the client has implicit flow disabled.

### Keycloak WebAuthn execute-actions token replay

- Advisory: [GHSA-w4p5-rfh6-cwrv / CVE-2026-37982](https://github.com/advisories/GHSA-w4p5-rfh6-cwrv)
- Product: `org.keycloak:keycloak-services`
- Affected versions: before `26.6.2`
- Required position: attacker who obtains a victim's execute-actions email link in an authorized lab scenario
- Boundary: execute-actions tokens for WebAuthn enrollment must be single-use and bound to the intended action/session.

### Keycloak evaluate-scopes Admin API cross-user disclosure

- Advisory: [GHSA-rrv7-3mqf-hxfr / CVE-2026-37978](https://github.com/advisories/GHSA-rrv7-3mqf-hxfr)
- Product: `org.keycloak:keycloak-services`
- Affected versions: before `26.6.2`
- Required position: low-privilege administrator with `view-clients`
- Boundary: `evaluate-scopes` Admin API calls must not accept arbitrary `userId` values that expose cross-role identity or authorization data.

### Keycloak token introspection audience bypass

- Advisory: [GHSA-4x37-hw65-52w8 / CVE-2026-37979](https://github.com/advisories/GHSA-4x37-hw65-52w8)
- Product: `org.keycloak:keycloak-services`
- Affected versions: before `26.6.2`
- Required position: attacker-controlled confidential client with valid credentials in the realm
- Boundary: token introspection must enforce audience/resource-server separation before returning sensitive lightweight-token claims.

### Keycloak SAML input resource exhaustion

- Advisory: [GHSA-p5mv-gj8j-xqgf / CVE-2026-7307](https://github.com/advisories/GHSA-p5mv-gj8j-xqgf)
- Product: `org.keycloak:keycloak-saml-core`
- Affected versions: before `26.6.2`
- Required position: remote unauthenticated network access to a SAML endpoint
- Boundary: XML/SAML parsing must reject pathological inputs before CPU or worker-thread starvation.

### MLflow Assistant browser-mediated local command execution

- Advisory: [GHSA-67c5-x5mf-rppq / CVE-2026-2611](https://github.com/advisories/GHSA-67c5-x5mf-rppq)
- Product: `mlflow`
- Affected version: `3.9.0`
- Fixed version: `3.10.0`
- Required configuration: MLflow Assistant running locally with `/ajax-api` endpoints reachable from the victim browser
- Boundary: loopback developer tools must enforce origin and capability controls before changing assistant configuration or invoking local agent execution paths.

## Recon workflow

1. Confirm authorization for identity-provider, SSO, local-development-tool, and destructive/resource-impact testing. Keep DoS validation in a lab unless the owner has explicitly provisioned a safe target.
2. Inventory evidence before probing:
   - Keycloak version from admin console, container tags, Maven/SBOM data, `/realms/{realm}` metadata, owner-provided build manifests, or HTTP banners where exposed.
   - Client configuration for wildcard redirect URIs, disabled implicit flow, SAML endpoints, WebAuthn required actions, confidential clients, and delegated admin roles.
   - MLflow version, Assistant enablement, local bind address, exposed `/ajax-api` paths, and whether a browser page can reach the local service.
3. Prioritize targets where the boundary is reachable:
   - public OIDC authorization endpoints with wildcard redirect clients;
   - SSO flows that reuse `login-actions` links or restart flows;
   - low-privilege delegated-admin accounts with `view-clients`;
   - confidential client credentials issued to tenant-controlled apps;
   - developer workstations, notebooks, or lab hosts running MLflow Assistant.
4. Capture raw HTTP requests and responses with tokens redacted. For identity tests, controlled accounts and canary clients are better than real users.

## Safe validation patterns

### Redirect canonicalization with wildcard clients

Use a lab client or a program-provided canary client whose redirect allowlist intentionally contains a wildcard.

1. Record the client's allowed redirect pattern, for example `https://*.client.example.test/*` or an equivalent owner-approved wildcard.
2. Send an authorization request with a canary `redirect_uri` containing multiple `@` characters in the authority/user-info portion. Keep the destination under a domain you control for testing.
3. Inspect whether Keycloak accepts the redirect and where the final `Location` points.
4. Interpret results:
   - **Contained:** the malformed URI is rejected or normalized before wildcard comparison.
   - **Vulnerable boundary:** the authorization flow permits a redirect target outside the intended client origin because parser disagreement falls back to wildcard matching.

### Login-actions restart session ownership

Use two controlled browser sessions and avoid real user phishing.

1. From session A, initiate a login or required-action flow and capture only the lab session handle/link.
2. In session B, visit the restart path using session A's handle without the matching cookies or CSRF state.
3. Observe whether the flow resets or progresses in a way that lets session B control session A's required-action form.
4. Contained behavior rejects the restart or requires matching cookie ownership. Vulnerable behavior accepts the foreign handle and changes authentication-flow state.

### Disabled implicit-flow token delivery

1. Confirm a lab client has implicit flow disabled.
2. Authenticate as a controlled low-privilege user.
3. Exercise restart/resume paths while attempting to force response data that would deliver an access token in the front channel.
4. Evidence should show the client configuration, request parameters, and whether an access token appears in a URL fragment, response body, log, or referrer. Redact the token value.

### WebAuthn execute-actions replay

Only use a canary user and email inbox controlled by the assessment team.

1. Generate a WebAuthn enrollment or required-action email for the canary account.
2. Use the link once to enroll a test authenticator.
3. Attempt to reuse the same execute-actions token from a separate session or after the intended action is complete.
4. Contained behavior invalidates the token after first use and binds it to the expected action. Vulnerable behavior allows another authenticator enrollment or account state change.

### Admin API evaluate-scopes user binding

1. Use a delegated admin account with `view-clients` only.
2. Call the evaluate-scopes endpoint for a client with the delegated admin's own `userId` and record expected fields.
3. Repeat with another canary user's ID where the delegated admin should not see identity or authorization details.
4. Contained behavior rejects or redacts cross-user data. Vulnerable behavior returns PII, roles, claims, or authorization details for the arbitrary `userId`.

### Token introspection audience separation

1. Register or use an attacker-controlled confidential client in a lab realm.
2. Obtain a token intended for a different resource server or audience.
3. Submit the token to the introspection endpoint using only the attacker-controlled confidential client's credentials.
4. Contained behavior enforces audience/client separation and withholds claims. Vulnerable behavior returns sensitive token claims intended for another resource server.

### SAML parser resource boundary

Do not stress production identity infrastructure. For live programs, stop at version/configuration evidence unless the owner provides a lab.

1. In a lab, send small malformed SAML/XML canaries first and confirm parser errors return quickly.
2. Increase complexity only enough to show abnormal processing time, CPU spike, or worker exhaustion compared with baseline.
3. Evidence should include timing deltas and lab resource graphs, not a production outage.

### MLflow Assistant origin and capability boundary

Use a lab workstation or container with MLflow Assistant enabled.

1. Confirm the local Assistant service and `/ajax-api` endpoints are reachable only as intended.
2. From a different browser origin, issue benign cross-origin requests that attempt to read configuration or toggle a harmless canary setting.
3. Confirm whether origin checks, CSRF checks, or preflight behavior block the request before any assistant capability changes.
4. Do not execute arbitrary commands for proof. A denied cross-origin configuration change is contained; a successful canary configuration write from a foreign origin is enough to demonstrate the boundary failure.

## Evidence to capture

- Version and feature proof: Keycloak artifact/version, MLflow version, client settings, enabled SAML/WebAuthn/Admin API paths, or owner-provided SBOM.
- Controlled-account model: which canary users, clients, and realms were used.
- Raw requests/responses showing redirect, restart, introspection, evaluate-scopes, or MLflow `/ajax-api` boundary behavior with credentials and tokens redacted.
- For WebAuthn and execute-actions tests, token first-use and replay timestamps.
- For DoS/resource-boundary tests, lab-only timing and resource measurements.

## Report framing

Frame findings as missing binding checks before trust is transferred:

- Redirect URI validation must bind to the intended origin after a single canonical parser view.
- Restart and required-action links must bind to session ownership, CSRF state, and single-use semantics.
- OIDC token delivery and introspection must bind to client configuration and audience.
- Delegated admin APIs must bind requested `userId` values to authorized visibility.
- Local AI/developer assistants must bind browser origins and capabilities before agent execution is reachable.

Avoid reporting only "vulnerable version found" unless the affected feature is enabled and reachable. Strong proofs show a minimal canary boundary crossing without harvesting real credentials, disclosing real user data, or disrupting production.

## Sources

- GitHub Advisory Database: [GHSA-rp95-xpg9-c2cq / CVE-2026-7504](https://github.com/advisories/GHSA-rp95-xpg9-c2cq)
- GitHub Advisory Database: [GHSA-hf67-5vvq-fm3r / CVE-2026-7507](https://github.com/advisories/GHSA-hf67-5vvq-fm3r)
- GitHub Advisory Database: [GHSA-hq3p-w4xv-x7vp / CVE-2026-7571](https://github.com/advisories/GHSA-hq3p-w4xv-x7vp)
- GitHub Advisory Database: [GHSA-w4p5-rfh6-cwrv / CVE-2026-37982](https://github.com/advisories/GHSA-w4p5-rfh6-cwrv)
- GitHub Advisory Database: [GHSA-rrv7-3mqf-hxfr / CVE-2026-37978](https://github.com/advisories/GHSA-rrv7-3mqf-hxfr)
- GitHub Advisory Database: [GHSA-4x37-hw65-52w8 / CVE-2026-37979](https://github.com/advisories/GHSA-4x37-hw65-52w8)
- GitHub Advisory Database: [GHSA-p5mv-gj8j-xqgf / CVE-2026-7307](https://github.com/advisories/GHSA-p5mv-gj8j-xqgf)
- GitHub Advisory Database: [GHSA-67c5-x5mf-rppq / CVE-2026-2611](https://github.com/advisories/GHSA-67c5-x5mf-rppq)
