# XML, SQL, and dynamic-object boundary batch

**Signal:** The **2026-05-08 20:15 UTC** advisory scan found multiple libraries where attacker-controlled structure crossed into serialization, query generation, or object mutation: `xmldom` XML injection/recursion, NocoBase SQL validation gaps, MikroORM identifier/JSON-path SQLi, and `mathjs` dynamic-object modification.

## Advisory cluster

- **xmldom XML serialization flaws** — [GHSA-2v35-w6hq-6mfw](https://github.com/advisories/GHSA-2v35-w6hq-6mfw), [GHSA-f6ww-3ggp-fr8h](https://github.com/advisories/GHSA-f6ww-3ggp-fr8h), [GHSA-x6wf-f3px-wcqx](https://github.com/advisories/GHSA-x6wf-f3px-wcqx), [GHSA-j759-j44w-7fr8](https://github.com/advisories/GHSA-j759-j44w-7fr8): `@xmldom/xmldom < 0.8.13` and `>=0.9.0,<0.9.10`, plus legacy `xmldom <=0.6.0`, can hit uncontrolled recursion or inject XML through unvalidated doctype, processing-instruction, and comment serialization.
- **NocoBase SQL validation bypasses** — [GHSA-wrwh-c28m-9jjh](https://github.com/advisories/GHSA-wrwh-c28m-9jjh), [GHSA-4948-f92q-f432](https://github.com/advisories/GHSA-4948-f92q-f432): `@nocobase/plugin-collection-sql < 2.0.39` missed `checkSQL`, and `@nocobase/database < 2.0.39` had recursive eager-loading SQLi through string concatenation.
- **MikroORM runtime identifier / JSON-path SQL injection** — [GHSA-cfw5-68c4-ffqp](https://github.com/advisories/GHSA-cfw5-68c4-ffqp): `@mikro-orm/sql <= 7.0.13` and `@mikro-orm/knex <= 6.6.13` accepted unsafe runtime-controlled identifiers and JSON-path keys.
- **mathjs dynamic object attribute modification** — [GHSA-jvff-x2qm-6286](https://github.com/advisories/GHSA-jvff-x2qm-6286): `mathjs >= 13.1.0,<15.2.0` allowed unsafe modification of dynamically determined object attributes.

## Why this matters

Escaping values is not enough when user input can select syntax nodes: XML node kinds, SQL identifiers, JSON-path fragments, recursive eager-loading paths, or object attribute names. These need allowlisted structure, not value escaping alone.

## Triage

1. Patch `@xmldom/xmldom` to `0.8.13+` or `0.9.10+`; replace legacy `xmldom` where possible.
2. Patch NocoBase packages to `2.0.39+`, MikroORM packages past the fixed release, and `mathjs` to `15.2.0+`.
3. Search for APIs exposing XML node construction, custom SQL fragments, sort/filter/include fields, JSON-path keys, formula expressions, or object mutation to end users.
4. Add regression tests with recursive XML trees, malicious comments/processing instructions, SQL identifier metacharacters, JSON-path escapes, and prototype-ish attribute names.

## Durable controls

- Represent query structure with typed builders and enum allowlists; never concatenate identifiers from request fields.
- Treat serializer metadata as untrusted output, requiring validation just like element text.
- Enforce parser/serializer recursion and output-size budgets.
- Run expression engines with frozen prototypes, narrow scopes, and explicit mutation bans.
- Log rejected structural tokens so probes become visible before they become exploit paths.
