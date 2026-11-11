---
title: Control-plane identity, analyst-project, and connection-state boundaries
---

# Control-plane identity, analyst-project, and connection-state boundaries

Source: hourly offensive-security scan of CISA KEV and GitHub Security Advisories on 2026-08-03. The N-able, OpenEMR, Ghidra, and 389 Directory Server records were unreviewed database entries at scan time; CISA added the N-able issue to KEV on August 3. Confirm the exact revision, configuration, role, route, and fixed behavior before reporting.

This wave yields four durable operator patterns: incomplete fixes that leave alternate authentication paths open, OAuth client registration detached from later grant authority, analyst-project state selecting an executable helper, and a failed bind leaving authenticated connection state behind.

Primary sources:

- N-able N-central [CVE-2026-18577 / GHSA-qgcm-97x5-6q8q](https://github.com/advisories/GHSA-qgcm-97x5-6q8q), [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [2026.3 HF1 release notes](https://documentation.n-able.com/N-central/Release_Notes/GA/Content/N-central_2026.3_HF1_Release_Notes.htm), and [vendor status notice](https://status.n-able.com/2026/08/02/n-central-2026-3-hotfix-1-mitigation-for-cve-2026-18577/);
- OpenEMR OAuth MFA bypass [GHSA-g6r6-jr7g-hg95 / CVE-2026-67611](https://github.com/advisories/GHSA-g6r6-jr7g-hg95), dynamic-client scope boundary [GHSA-7h45-2j8g-37rm / CVE-2026-67610](https://github.com/advisories/GHSA-7h45-2j8g-37rm), backup import [GHSA-v687-rxcc-g864 / CVE-2026-39931](https://github.com/advisories/GHSA-v687-rxcc-g864), and category-tree evaluation chain [GHSA-pj78-c8jq-8xhf / CVE-2026-39932](https://github.com/advisories/GHSA-pj78-c8jq-8xhf);
- Ghidra Swift demangler project-state execution [GHSA-mfcj-9frg-f2r4 / CVE-2026-18718](https://github.com/advisories/GHSA-mfcj-9frg-f2r4) and the [upstream Ghidra advisory](https://github.com/NationalSecurityAgency/ghidra/security/advisories/GHSA-pcfh-853f-q3gh); and
- 389 Directory Server SASL PLAIN state handling [GHSA-q924-9ph6-5h92 / CVE-2026-18651](https://github.com/advisories/GHSA-q924-9ph6-5h92).

!!! warning "Disposable labs and no-op sinks only"
    Use isolated N-central/OpenEMR labs, synthetic users and FHIR records, generated OAuth keys, a disposable Ghidra project, and a local directory-service fixture. Replace session, token, SQL, process-start, and privileged LDAP sinks with recorders. Never test an Internet-reachable management server, retrieve patient data, modify access-control tables, execute project-supplied binaries, or reuse real credentials.

## Boundary map

| Surface | First trusted fact | Detached authority or state | Bounded positive |
| --- | --- | --- | --- |
| N-central | one patched login route rejects the old path | alternate route, content type, method, or continuation still reaches account recovery/session logic | no-op session sink records an unauthorized synthetic principal |
| OpenEMR password grant | username/password are valid | OAuth route bypasses the web MFA ceremony | fake token sink receives a grant before the synthetic second factor succeeds |
| OpenEMR dynamic registration | a client registration is accepted or approved | request-supplied key and scopes become system-wide client authority | authorization recorder preserves an out-of-policy canary scope |
| OpenEMR import/eval chain | admin may import backup material | imported SQL changes a value later interpreted as PHP | SQL recorder and patched evaluator show the same inert marker crossing both stages |
| Ghidra project | analyst opens a project | persisted Swift tool-directory state chooses a native executable | patched process launcher receives the outside-project canary binary path |
| 389 Directory Server | credentials are correct but account is locked | connection bind identity is installed before lock rejection and not rolled back | a same-connection authorization recorder observes the locked synthetic identity after failed bind |

## 1. Re-test the whole authentication route family after an incomplete fix

CISA describes CVE-2026-18577 as an exploited N-central authentication bypass and account-takeover issue caused by an incomplete fix for the predecessor authentication flaw. Public records do not provide a safe request-level proof, so use them for scoping and version evidence,not as permission to guess against exposed appliances.

1. Obtain an approved N-central lab snapshot from before the original fix, an intermediate build containing that fix, and 2026.3 HF1 or a vendor-confirmed later build.
2. Create one disposable ordinary user and patch the final session/account-change sink to record principal ID and route, then return without creating a session or changing credentials.
3. Derive the authentication route family from the local application/UI: login, recovery, enrollment, API, legacy/versioned endpoints, mobile/integration paths, and redirect/continuation handlers.
4. For each route, vary one parser dimension at a time: method, content type, duplicate parameter, omitted field, encoded separator, path normalization, and direct final-step navigation. Do not brute-force tokens or credentials.
5. Compare pre-fix, intermediate, and HF1 decisions. Capture route, normalized route, middleware chain, authenticated principal before and after handling, and whether the no-op sink was reached.

The reportable chain is **original route blocked by the intermediate fix -> semantically equivalent alternate route/state reaches the same no-op account/session sink -> HF1 rejects both**. Version fingerprinting or KEV presence alone is not proof. Do not publish or run a production bypass request.

## 2. Separate OpenEMR credential, MFA, client, scope, and code-evaluation decisions

Use generated users, patients, FHIR records, OAuth clients, and keys in a network-isolated OpenEMR lab. Patch token issuance to return only a random canary and patch SQL/evaluation sinks before testing.

### Password grant versus web MFA

1. Require a synthetic second factor for user A and verify that the ordinary web flow does not reach the session recorder before that factor succeeds.
2. Register only a disposable public client through the lab's documented dynamic-registration flow.
3. Submit user A's generated credentials to each enabled OAuth grant route while the second factor remains incomplete.
4. Record client type, grant type, user authentication factors, MFA state, requested scopes, policy decision, and token-recorder call.
5. Repeat with password grant disabled, an ordinary user without MFA as a reachability control, invalid credentials, and a corrected build.

A positive is **valid first factor + incomplete MFA -> alternate OAuth grant -> fake token sink invoked for user A**. It is not a password bypass; the defect is that the alternate channel fails to preserve the MFA requirement.

### Dynamic registration versus final client authority

Build a decision table covering unauthenticated registration, administrator approval, client key provenance, grant type, requested scope, approved scope, and final token scope. Use a self-generated RSA key and harmless scopes over synthetic FHIR resource types. Patch the FHIR data layer to return only selected resource IDs.

The bounded positive is **request-supplied client/key -> approval or registration preserves an out-of-policy system scope -> client-credentials token recorder receives that scope**. If administrative approval explicitly displays and authorizes the exact key, grant, and scope, report that fact rather than claiming pre-auth access. Never retrieve medical records.

### Backup import to later evaluator

Do not upload active SQL or PHP. Replace the database CLI/process launcher with an argv-and-stdin recorder and replace the category-tree evaluator with a callback that records its input without evaluating it.

1. Import a benign SQL fixture containing only a uniquely random inert marker for a disposable category row.
2. Determine whether the import path would pass caller-supplied statements to the database client without an application-enforced grammar or object allowlist.
3. Seed the same marker directly in the disposable database fixture; do not alter schema types, users, grants, triggers, procedures, or filesystem settings.
4. Instantiate each documented category-tree consumer under anonymous, low-role, and admin contexts while the evaluator remains patched.
5. Capture role, import authorization, process argv/stdin shape, selected category field, evaluator call, and fixed-build behavior.

The safe chain proof is **admin-controlled import reaches unrestricted SQL recorder + synthetic category value later reaches evaluator recorder**. Keep the two primitives explicit and never execute SQL that changes authority or PHP that starts a process.

## 3. Treat Ghidra project state as executable configuration

A project can be untrusted even when the analyzed binary is expected to be hostile. The cited Ghidra issue describes persisted Swift tool-directory state being restored and used to select a native demangler without integrity validation or a fresh prompt.

1. Create a disposable affected-version project and an inert executable canary whose only behavior would be writing a random marker inside the lab. Do not run it.
2. Place the canary outside the trusted Ghidra installation/tool roots and encode only its parent directory through the affected project-state field.
3. Patch Java process creation so it logs executable path, argv, working directory, environment keys, and caller, then aborts.
4. Open the project with automatic analysis disabled, then enable only the Swift demangler analyzer. Determine the earliest action that reaches the recorder.
5. Add controls for a clean project, a missing path, a trusted bundled tool path, project import versus reopen, and a corrected Ghidra build.

Report **untrusted project state -> restored Swift tool directory -> native process recorder selects attacker-controlled path without a fresh trust decision**. Opening a malicious sample alone is not the precondition described here, and no executable needs to run to prove the boundary.

## 4. Verify failed authentication rolls back connection identity

For the 389 Directory Server case, use one generated locked account, one active account, and a test entry visible only to the locked account. Instrument authorization so it records effective bind DN and operation but returns no entry data.

1. Open a fresh LDAP connection and attempt SASL PLAIN with correct credentials for the locked account.
2. Confirm the bind response reports failure, but keep that exact transport connection open.
3. Send one harmless search or compare operation targeting the synthetic protected entry.
4. Repeat on a new connection, after an explicit anonymous bind, with wrong credentials, with the active account, and on a corrected build.
5. Capture bind result, connection ID, identity before/after the bind, lock-policy decision, rollback event, and authorization-recorder identity.

A positive is **locked-account bind reports failure -> same connection retains the locked account DN -> one authorization recorder runs with that DN**. Do not enumerate directory data, spray credentials, or call this credential bypass: valid credentials are still required, while account-lock revocation is defeated.

## Reporting checklist

- [ ] Exact advisory review status, affected/fixed build, route, role, and configuration are recorded.
- [ ] N-central evidence compares original, intermediate, and HF1 behavior without publishing a live bypass request.
- [ ] OpenEMR password, MFA, client approval, key provenance, scopes, SQL import, and evaluator stages remain separate.
- [ ] Ghidra proof stops at a patched process-start recorder.
- [ ] LDAP proof preserves one connection and records identity rollback without returning directory content.
- [ ] Every positive uses synthetic principals, keys, records, paths, and markers.
