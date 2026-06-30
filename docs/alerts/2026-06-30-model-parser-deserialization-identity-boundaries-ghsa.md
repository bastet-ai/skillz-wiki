# Model parser, deserialization, and identity-extractor boundary checks

Source: hourly offensive-security scan, 2026-06-30. Primary entries: GitHub Advisory Database [GHSA-j35x-w4gj-pf7w](https://github.com/advisories/GHSA-j35x-w4gj-pf7w) / CVE-2025-10996, [GHSA-8j3x-m868-cpw8](https://github.com/advisories/GHSA-8j3x-m868-cpw8) / CVE-2025-10995, [GHSA-m5gw-83w2-7749](https://github.com/advisories/GHSA-m5gw-83w2-7749) / CVE-2026-48207, [GHSA-m3v4-v5gx-7wf5](https://github.com/advisories/GHSA-m3v4-v5gx-7wf5) / CVE-2026-47117, and [GHSA-293q-567p-wmwq](https://github.com/advisories/GHSA-293q-567p-wmwq) / CVE-2026-47838.

These advisories are durable for operators because they expose repeatable trust-boundary tests: chemistry conversion services parsing untrusted SMILES or compressed molecule files, Python deserialization policies failing to cover reduce-state restoration, AI privacy-filter model names routing into `trust_remote_code=True`, and X.509 client-certificate CN parsing disagreeing with the authenticated identity actually selected.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-j35x-w4gj-pf7w](https://github.com/advisories/GHSA-j35x-w4gj-pf7w) / CVE-2025-10996 | Open Babel `OBSmilesParser::ParseSmiles` | crafted SMILES strings could write past a heap buffer when parsed through `obabel`, `OBConversion`, or language bindings before 3.2.0 | Scientific file-conversion APIs are attack surface when web apps, notebooks, LIMS, or cheminformatics pipelines accept user molecule text. Prove in a lab harness only. |
| [GHSA-8j3x-m868-cpw8](https://github.com/advisories/GHSA-8j3x-m868-cpw8) / CVE-2025-10995 | Open Babel bundled `zipstream` gzip reader | crafted gzip-compressed chemistry files reached an overlapping `memcpy` / out-of-bounds write path | Include compressed-wrapper variants in parser-boundary tests; a safe extension or declared format does not remove decompressor risk. |
| [GHSA-m5gw-83w2-7749](https://github.com/advisories/GHSA-m5gw-83w2-7749) / CVE-2026-48207 | Apache Fory PyFory `ReduceSerializer` | reduce-state restoration and global-name resolution bypassed documented `DeserializationPolicy` validation hooks when strict mode was disabled | Treat policy-based deserializers as sinks: every constructor, reducer, global lookup, and state-restore path needs canary deny/allow tests. |
| [GHSA-m3v4-v5gx-7wf5](https://github.com/advisories/GHSA-m3v4-v5gx-7wf5) / CVE-2026-47117 | OpenMed privacy-filter model loader | user-controlled `model_name` substring matching routed attacker repositories into Hugging Face loading with `trust_remote_code=True` | AI service assessments should test model-name routing, repository authority, `auto_map`, and tokenizer/model config execution boundaries with inert repos. |
| [GHSA-293q-567p-wmwq](https://github.com/advisories/GHSA-293q-567p-wmwq) / CVE-2026-47838 | Spring Security `SubjectDnX509PrincipalExtractor` | malformed X.509 certificate CN values could make the extractor read the wrong username | mTLS/client-cert deployments need identity-extractor parser-differential tests: certificate subject string parsing must match the principal mapping policy. |

Adjacent Open Babel NULL-pointer and out-of-bounds-read advisories, duplicate Open Babel records, Apache Fory generic duplicate summaries, Spring Security duplicate advisory IDs, and availability-only parser/resource issues were processed without separate promotion because they did not add a distinct workflow beyond the boundaries above.

## Replayable validation boundaries

### Open Babel untrusted chemistry parser harness

- Preconditions: isolated lab host or CI job with vulnerable and fixed Open Babel versions, ASAN/UBSAN if building from source, and disposable molecule inputs only.
- Exercise both direct SMILES input and gzip-wrapped chemistry files through the same path the target uses: `obabel`, `OBConversion`, Python/Ruby/Java bindings, upload converters, or notebook helpers.
- Positive evidence is limited to sanitizer crash logs, process exit status, parser-format decision tables, and fixed-version negative controls. Do not attempt exploit reliability, shellcode, memory disclosure, or production conversion-service crashes.
- Include wrapper cases: raw molecule text, `.smi`, declared alternate formats, gzip-compressed files, and API calls where the service auto-detects format from extension or content.
- Negative controls: Open Babel 3.2.0 or later, input size/time limits, parser isolation, and format allowlists bound to the actual conversion code path.

### PyFory policy-bypass deserialization harness

- Preconditions: disposable Python process, affected `pyfory` version, strict mode disabled only in the lab, and a custom `DeserializationPolicy` that denies an inert canary callable/class.
- Create paired serialized payloads that try the same canary through normal object paths, reduce-state restoration, and global-name/module-attribute resolution.
- Positive evidence is a policy-denied canary being resolved or invoked through a reducer path while the same policy blocks the direct path.
- Keep canaries harmless: set an in-memory flag, return a marker string, or write to a temporary lab file. Do not deserialize payloads that launch processes, read environment variables, import cloud SDKs, or touch credentials.
- Negative controls: PyFory 1.0.0 or later, strict mode enabled, reducer/global lookup tests in CI, and policy hooks covering every restoration path.

### OpenMed privacy-filter model-routing harness

- Preconditions: owned OpenMed lab below 1.5.2, a disposable Hugging Face-compatible repository under your control, inert `auto_map` code that records only a marker, and no production PHI/PII.
- Send model names that contain the privacy-filter substring in unexpected positions, such as an owned namespace/repository name with `privacy-filter` embedded, and record which dispatcher path runs.
- Positive evidence is the service loading code or tokenizer/model config from the attacker-controlled repository because substring routing selected the privacy-filter loader with `trust_remote_code=True`.
- Do not load untrusted third-party repositories, exfiltrate prompts, process patient data, or run commands on production inference workers.
- Negative controls: OpenMed 1.5.2 or later, exact model allowlists, `trust_remote_code=False` for user-selectable models, and repository-owner pinning.

### Spring Security X.509 principal parser-differential harness

- Preconditions: lab Spring Security app using X.509 client-certificate authentication, affected `spring-security-web`, disposable users, and a test CA accepted only by the lab.
- Generate certificates with CN values that include escaping, separators, repeated attributes, unusual ordering, and malformed-but-accepted subject strings.
- Build a table for each certificate: raw subject DN, parsed CN from `SubjectDnX509PrincipalExtractor`, expected username, authenticated username, and authorization result for a harmless route.
- Positive evidence is a certificate authenticating as a different disposable user than the mapping policy intends.
- Do not use real client certificates, production CAs, customer usernames, or privileged admin routes.
- Negative controls: `SubjectX500PrincipalExtractor`, fixed Spring Security versions, strict subject mapping, and explicit certificate-to-account binding tests.

## Reporting notes

- Lead with the exact boundary crossed: **untrusted molecule input to native parser**, **deserialization policy to reduce/global lookup**, **model-name substring to remote code loader**, or **certificate subject string to authenticated username**.
- Include affected and fixed versions, the minimal canary input shape, expected denial or safe parse, observed result, and a fixed-version negative control.
- Keep evidence scoped and inert: sanitizer traces, temp-file markers, owned model repos, fake users, lab CAs, and synthetic molecule files only.
