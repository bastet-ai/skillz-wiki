# Apache storage, model, and search-boundary batch

**Signal:** The **2026-05-08 18:15 UTC** advisory scan added a broad Apache-centered boundary batch: Polaris vended storage credentials escaped table scope, OpenNLP model/dictionary loaders trusted attacker-controlled metadata too early, and Atlas DSL search allowed query logic alteration in a non-default execution mode.

## Advisories covered

- **Apache Polaris GCS credential access-boundary injection** — [GHSA-fc3h-c6h7-r83j](https://github.com/advisories/GHSA-fc3h-c6h7-r83j): `org.apache.polaris:polaris-core < 1.4.1`; patch to `1.4.1+`.
- **Apache Polaris S3 wildcard table-name credential broadening** — [GHSA-vxgg-mqx2-3w59](https://github.com/advisories/GHSA-vxgg-mqx2-3w59): `polaris-core < 1.4.1`; patch to `1.4.1+`.
- **Apache Polaris staged-create location credential vending before validation** — [GHSA-8ggj-j522-h5qf](https://github.com/advisories/GHSA-8ggj-j522-h5qf): `polaris-runtime-service < 1.4.1`; patch to `1.4.1+`.
- **Apache OpenNLP binary model count OOM** — [GHSA-659w-93r5-9j6m](https://github.com/advisories/GHSA-659w-93r5-9j6m): `opennlp-tools < 2.5.9` and `3.0.0-M1..M2`; patch to `2.5.9+` or `3.0.0-M3+`.
- **Apache OpenNLP manifest-driven class initialization** — [GHSA-cx4m-2p55-rw7j](https://github.com/advisories/GHSA-cx4m-2p55-rw7j): same affected ranges; patch to `2.5.9+` or `3.0.0-M3+`.
- **Apache OpenNLP dictionary XXE** — [GHSA-4v8g-86x5-3vrc](https://github.com/advisories/GHSA-4v8g-86x5-3vrc): same affected ranges; patch to `2.5.9+` or `3.0.0-M3+`.
- **Apache Atlas DSL search code/query injection** — [GHSA-35xx-9xrg-gwhf](https://github.com/advisories/GHSA-35xx-9xrg-gwhf): `org.apache.atlas:apache-atlas >= 0.8, < 2.5.0`; patch to `2.5.0+`; for `>=2.0.0`, exposure requires non-default `atlas.dsl.executor.traversal=false`.

## Why this is durable

The shared failure is **letting names, locations, model metadata, or query strings become policy**. Storage credential vendors must not translate table identifiers into IAM/CEL conditions before escaping and overlap validation. Model loaders must not execute class initializers, allocate attacker-sized arrays, or parse XML entities before provenance and parser controls. Search DSLs must not let grammar-valid input alter the intended traversal semantics.

## Immediate triage

1. Patch Polaris to `1.4.1+`, OpenNLP to `2.5.9+` / `3.0.0-M3+`, and Atlas to `2.5.0+`.
2. For Polaris, list recently issued temporary storage credentials and review access logs for wildcard-like namespace/table names, staged custom locations, and cross-table object reads/writes.
3. Revoke or expire vended credentials issued before the Polaris patch if table names or locations were user-controlled.
4. For OpenNLP, block untrusted `.bin` models, dictionaries, and model archives until all consumers are patched; hunt for OOMs, outbound HTTP/file entity resolution, and unexpected class initialization during model load.
5. For Atlas, confirm whether `atlas.dsl.executor.traversal=false` was enabled; if so, review DSL search logs for grammar edge cases and unexpected data exposure.

## Durable controls

- Build storage policies from canonical validated resource objects, not string-concatenated identifiers.
- Escape policy languages as policy languages: IAM wildcards, GCS CEL strings, URI paths, and table identifiers each need separate encoders.
- Validate and reserve table locations before issuing any credential for them.
- Treat model files as executable-adjacent inputs: require signatures/provenance, size limits, parser hardening, class allowlists, and sandboxed load workers.
- Use secure XML parser defaults by construction and make DTD/entity support opt-in only for trusted paths.
- Test DSL/search endpoints with grammar-valid payloads that attempt to change traversal logic, not only syntax-invalid injection strings.
