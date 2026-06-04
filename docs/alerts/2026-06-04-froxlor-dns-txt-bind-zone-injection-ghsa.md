# Froxlor DNS TXT BIND zone injection boundary

## Operator value

Froxlor advisory [GHSA-37m5-m4q3-fc6x / CVE-2026-41234](https://github.com/advisories/GHSA-37m5-m4q3-fc6x) describes a newline-injection bug in the `DomainZones.add` API for TXT records. An authenticated customer with DNS editing enabled can place line breaks inside TXT content; Froxlor then writes the content into a generated BIND zone file, allowing extra DNS records or BIND directives to be injected when the DNS rebuild cron runs.

For authorized testing, treat this as a control-plane-to-DNS integrity boundary: can a scoped hosting customer alter only the DNS records they are permitted to manage, or can they inject additional zone-file lines outside the TXT value?

## Affected surface

- Product: Froxlor / `froxlor/froxlor`
- Affected versions: `<= 2.3.6`
- Fixed version: `2.3.7`
- Required position: authenticated customer account with DNS editing enabled for a delegated domain
- Trigger path: `DomainZones.add` API with `type=TXT`
- Downstream effect: generated BIND zone output after the DNS rebuild cron/materialization step

## Recon workflow

1. Confirm the assessment scope includes the Froxlor panel and delegated test domains.
2. Fingerprint Froxlor only with non-invasive checks:

   ```bash
   httpx -silent -title -tech-detect -status-code -path / -u https://panel.example.test
   ```

3. Verify whether the scoped customer role can create TXT records through the API or UI.
4. Identify the exact version from authorized admin evidence, package inventory, release metadata, or an agreed test environment. Do not infer exploitability from a login page alone.

## Safe validation pattern

Use an isolated delegated lab domain that you are explicitly allowed to modify. Avoid `$INCLUDE`, `$GENERATE`, resolver-impacting records, or production zones.

1. Create a baseline TXT record and capture the rendered value with `dig`:

   ```bash
   dig +short TXT baseline.lab.example.test @ns1.lab.example.test
   ```

2. Attempt a benign newline-boundary payload that would create only a harmless canary record if the zone writer fails to contain TXT content:

   ```text
   "owned-canary"
   canary.lab.example.test. 60 IN TXT "froxlor-newline-boundary"
   ```

3. Wait for the agreed DNS rebuild window or trigger only the approved lab rebuild.
4. Query for the canary:

   ```bash
   dig +short TXT canary.lab.example.test @ns1.lab.example.test
   ```

5. Record both outcomes:
   - **Contained:** the newline is rejected, escaped, or remains inside the original TXT value.
   - **Vulnerable:** a separate `canary.lab.example.test` TXT record appears, or the zone file contains an extra line derived from the TXT content.

## Evidence to capture

- Froxlor version and how it was verified.
- Customer role/permission that was allowed to edit DNS records.
- API/UI request metadata with secrets redacted.
- Before/after DNS answers for the baseline and canary names.
- Timing of DNS rebuild/materialization.
- Confirmation that validation used a delegated lab domain and inert TXT canary only.

## Report framing

Emphasize the broken trust boundary: customer-controlled TXT content crossed into BIND zone syntax without newline/metacharacter containment. The impact is not just a malformed TXT value; it can become unauthorized DNS-record or directive injection in the generated zone for a domain the panel manages.

## Sources

- GitHub Advisory Database: [GHSA-37m5-m4q3-fc6x / CVE-2026-41234](https://github.com/advisories/GHSA-37m5-m4q3-fc6x)
- Froxlor project advisory: [GHSA-37m5-m4q3-fc6x](https://github.com/froxlor/froxlor/security/advisories/GHSA-37m5-m4q3-fc6x)
- Froxlor fixed release: [2.3.7](https://github.com/froxlor/froxlor/releases/tag/2.3.7)
