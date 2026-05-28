# Pimcore composite-index SQLi and FUXA secure-read boundary batch (GHSA, 2026-05-28)

**Signal:** GitHub Advisory Database published two follow-on CMS/ICS-control-plane issues with reusable offensive-testing value: a Pimcore class-definition import/save SQL injection through composite-index metadata, and a FUXA secure-mode guest-context read bypass for project, alarm, and scheduler APIs.

## Operator value

- `GHSA-r2f4-ff2p-xc64` / `CVE-2026-5394`: Pimcore `<= 12.3.6` lets an authenticated administrative user who can import or save DataObject class definitions inject composite-index metadata that is concatenated into `ALTER TABLE ... ADD INDEX (...)` statements.
- `GHSA-c8g3-x47w-8q7p`: withdrawn duplicate of the Pimcore advisory; track it only for external-reference matching.
- `GHSA-r9g5-7q8j-958c` / `CVE-2026-47718`: FUXA `1.3.0-2773` with `secureEnabled=true` converts missing or invalid tokens into guest context and still returns project, alarm, and scheduler data from read APIs.

Use this only in authorized testing. Keep Pimcore proofs to disposable classes/tables in a lab or explicitly scoped staging system, and keep FUXA proofs read-only with redacted operational data. Do not modify production schemas, delete object data, interact with OT processes, or use disclosed project metadata for follow-on intrusion outside scope.

## 1. Pimcore DataObject composite-index SQL injection

### Where to look

- Pimcore `<= 12.3.6` deployments with administrative class-definition import or save workflows.
- Programs that grant limited CMS/admin roles for testing and include DataObject model customization in scope.
- Prior Pimcore findings where SQLi impact was limited to admin-only panels; this issue is still reportable when the trusted admin feature accepts attacker-controlled schema metadata and performs unsafe SQL construction.
- Chain analysis where schema alteration can support later deserialization, authorization-bypass, or data-integrity findings in an isolated lab.

### Safe validation workflow

1. Confirm the target version from `composer.lock`, release metadata, or an approved authenticated check.
2. Verify that the test account can import or save DataObject class definitions; do not assume low-privileged CMS users can reach this path.
3. In a lab or staging scope, create a disposable DataObject class with a harmless marker field and composite index.
4. Modify only the composite-index metadata in the imported JSON or class-definition save request.
5. Use a non-destructive marker proof such as a syntax-safe identifier change, controlled index creation failure, or a lab-only schema marker on the disposable class table.
6. Capture the source-to-sink path: imported `compositeIndices`, stored class definition, `updateCompositeIndices()`, and generated `ALTER TABLE` statement.
7. Stop before destructive clauses such as `DROP COLUMN`, data deletion, or table-wide changes unless the program explicitly approves destructive lab validation.

### What to report

- Affected Pimcore version and package name (`pimcore/pimcore`).
- Exact role/permission needed to import or save class definitions.
- The affected class ID/table names, with disposable proof artifacts clearly labeled.
- Evidence that `index_columns` or `index_key` reached SQL construction without identifier allowlisting or quoting.
- Why the proof does not depend on multi-statement execution: the high-signal primitive is additional `ALTER TABLE` clause injection inside a single statement.
- Business impact framed as schema integrity loss and chain support, not generic “admin can do anything.”

Reporting heuristic: strong reports distinguish **trusted admin feature** from **unsafe schema compiler**. Show that user-supplied metadata crosses from JSON/import UI into backend DDL, and keep the proof limited to a reversible test class.

## 2. FUXA secure-mode guest read bypass

### Where to look

- FUXA `1.3.0-2773` deployments, especially vendor demos, OT labs, staging HMIs, or scoped internal control-plane surfaces.
- Instances believed to be protected by `secureEnabled=true` where unauthenticated routes should reject missing or invalid tokens.
- Prior FUXA findings involving project disclosure, tag/value disclosure, Node-RED path confusion, or script test-mode execution; this issue can provide recon and chain-support context.

### Safe validation workflow

1. Confirm FUXA version and that `secureEnabled=true` is configured or claimed by the owner.
2. Send read-only unauthenticated requests to:
   - `GET /api/project`
   - `GET /api/alarms`
   - `GET /api/scheduler`
3. Repeat the same requests with an explicitly invalid `x-access-token` value.
4. Record only status codes, route names, response sizes, and heavily redacted field names unless sensitive-data handling is explicitly authorized.
5. Compare against an authenticated baseline when available to show the missing-token and invalid-token paths are being converted to guest context instead of rejected.
6. Do not query write endpoints, execute scripts, change device tags, or interact with connected PLC/OT systems as part of this proof.

### What to report

- FUXA version and secure-mode evidence.
- Token state tested: no token and invalid token.
- Endpoints returning `200 OK` and the categories of data exposed: project metadata, alarms, scheduler entries, script/device/tag references.
- Redacted sample fields showing operational impact without leaking process details.
- Relevant code-path hypothesis when useful: `verifyToken()` guest-context conversion plus route handlers that accept guest reads.

Reporting heuristic: present this as **secure-mode authentication boundary drift**. The most useful bug-bounty proof is not volume of data; it is the mismatch between configured secure mode and read APIs that still expose operational project internals to guest/invalid-token callers.

## Non-promoted adjacent items

- `GHSA-c8g3-x47w-8q7p` was treated as a withdrawn duplicate of `GHSA-r2f4-ff2p-xc64`, not a separate Skillz page.
- CISA KEV remained catalog `2026.05.28` with top entries already reflected or previously triaged for this wiki.
- PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, and Disclosed had no additional promotable offensive-operator deltas in this pass.

## References

- [Pimcore composite-index SQL injection (`GHSA-r2f4-ff2p-xc64`)](https://github.com/advisories/GHSA-r2f4-ff2p-xc64)
- [Pimcore duplicate advisory (`GHSA-c8g3-x47w-8q7p`)](https://github.com/advisories/GHSA-c8g3-x47w-8q7p)
- [Pimcore fix pull request](https://github.com/pimcore/pimcore/pull/19108)
- [Pimcore 12.3.7 release](https://github.com/pimcore/pimcore/releases/tag/v12.3.7)
- [FUXA secure-mode read bypass (`GHSA-r9g5-7q8j-958c`)](https://github.com/advisories/GHSA-r9g5-7q8j-958c)
- [FUXA 1.3.1 release](https://github.com/frangoteam/FUXA/releases/tag/v1.3.1)
