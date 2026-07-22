# Dompdf local-file confinement and existence-oracle checks

Sources: [GHSA-wvh6-f5jh-8gw4 / CVE-2026-55554](https://github.com/advisories/GHSA-wvh6-f5jh-8gw4) and [GHSA-7x2p-4jvh-6384 / CVE-2026-55555](https://github.com/advisories/GHSA-7x2p-4jvh-6384), published July 22, 2026. Both affect `dompdf/dompdf` before 3.1.6.

These advisories expose two reusable PDF-renderer testing boundaries: canonical paths checked as raw string prefixes, and local resource existence inferred from renderer resource consumption. They matter only when attacker-controlled or insufficiently sanitized HTML/CSS reaches Dompdf. Package presence alone is not proof of exploitability.

!!! warning "Authorized lab validation only"
    Use a disposable renderer, synthetic sibling directories, harmless image/font markers, and bounded worker resources. Do not enumerate production paths, reference `.env`, SSH, application-secret, or user files, or intentionally exhaust a shared PDF worker.

## Preconditions

- The application uses an affected Dompdf release.
- Untrusted content reaches `loadHtml()` or an equivalent rendering path with controllable resource-bearing HTML/CSS.
- For the confinement check, a known synthetic file exists in a sibling path whose name starts with the configured chroot path.
- For the oracle check, the lab exposes worker outcome, response class, or another stable signal and permits a tightly bounded resource test.

## Boundary summary

| Advisory | Source-to-sink boundary | Narrow proof |
| --- | --- | --- |
| [GHSA-wvh6-f5jh-8gw4](https://github.com/advisories/GHSA-wvh6-f5jh-8gw4) | Canonical local resource path -> prefix-only chroot comparison -> Dompdf resource load | A benign sibling-prefix image appears in the generated PDF while a non-prefix sibling is rejected. |
| [GHSA-7x2p-4jvh-6384](https://github.com/advisories/GHSA-7x2p-4jvh-6384) | Repeated `@font-face` local references -> file-dependent renderer work -> observable worker outcome | A synthetic existing marker and a matched nonexistent control produce a reproducible outcome differential near a lab-only resource threshold. |

## Sibling-prefix chroot validation

Create a temporary layout such as:

```text
/tmp/dompdf-lab/render-root/inside.png
/tmp/dompdf-lab/render-root-sibling/outside-canary.png
/tmp/dompdf-lab/unrelated/control.png
```

Configure the chroot as `/tmp/dompdf-lab/render-root/`. Render three minimal documents that differ only in the image path:

1. the in-root positive control;
2. the `render-root-sibling` canary;
3. the unrelated out-of-root negative control.

Capture the configured chroot, canonical path for each resource, Dompdf version, renderer warning/error state, and whether the known canary pixels appear in the output. A vulnerable result is **canonical sibling path shares the chroot string prefix -> prefix check accepts it -> outside-root canary is embedded**. Repeat on 3.1.6 or later; the fixed build should admit only the in-root control.

Do not generalize this to arbitrary file disclosure. Dompdf must support and successfully parse the referenced resource type, and the application must expose a controllable render sink.

## Bounded file-existence oracle validation

This issue relies on a resource-consumption differential, so avoid copying the advisory's high-iteration production-style test. In a disposable PHP worker with strict wall-time and memory controls:

1. Create one harmless synthetic font-like marker and one definitely absent path under the same temporary lab tree.
2. Establish that a single reference to either path does not crash the worker.
3. Increase identical `@font-face` references gradually under a low hard cap, recording request size, iteration count, peak memory, elapsed time, HTTP/result class, and PDF generation outcome.
4. Stop at the first stable distinction; do not continue after memory exhaustion or worker termination.
5. Repeat enough times to rule out ordinary renderer jitter, then compare 3.1.6 or later.

The reportable result is **controlled local path existence -> repeatable resource-use or response differential for matched synthetic paths**. An isolated timeout or crash is only availability evidence. Do not claim file contents were read, and do not probe guessed system or application paths.

## Evidence table

```text
Application render route:
Untrusted HTML/CSS field:
Dompdf version:
Configured chroot:
Canonical synthetic path:
Control class: in-root / sibling-prefix / unrelated / nonexistent
HTML/CSS resource sink:
Render result and marker presence:
Peak memory and elapsed time, if measured:
Fixed-version result:
```

Keep the two claims separate in reporting: sibling-prefix acceptance proves a confinement escape, while resource-behavior differences prove only a file-existence oracle under the tested worker configuration.
