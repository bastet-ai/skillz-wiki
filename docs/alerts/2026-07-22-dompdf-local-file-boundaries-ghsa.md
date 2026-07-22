# Dompdf local-file confinement and existence-oracle checks

Sources: [GHSA-wvh6-f5jh-8gw4 / CVE-2026-55554](https://github.com/advisories/GHSA-wvh6-f5jh-8gw4), [GHSA-7x2p-4jvh-6384 / CVE-2026-55555](https://github.com/advisories/GHSA-7x2p-4jvh-6384), [GHSA-cx96-42px-69fm / CVE-2026-56722](https://github.com/advisories/GHSA-cx96-42px-69fm), and [GHSA-j8qw-6jw8-r297 / CVE-2026-59943](https://github.com/advisories/GHSA-j8qw-6jw8-r297), published July 22, 2026. All affect `dompdf/dompdf` before 3.1.6.

These advisories expose three reusable PDF-renderer testing boundaries: canonical paths checked as raw string prefixes, local resource existence inferred from renderer resource consumption, and nested SVG resources resolved by a second parser without Dompdf's chroot policy. They matter only when attacker-controlled or insufficiently sanitized HTML/CSS reaches Dompdf. Package presence alone is not proof of exploitability.

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
| [GHSA-cx96-42px-69fm](https://github.com/advisories/GHSA-cx96-42px-69fm) | Data-URI SVG accepted by Dompdf -> nested external image resolved by `php-svg-lib` -> local resource read without Dompdf's chroot policy | A data-URI SVG embeds one synthetic image outside the render root while direct reference to the same marker is rejected. |

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

Keep the first two claims separate in reporting: sibling-prefix acceptance proves a confinement escape, while resource-behavior differences prove only a file-existence oracle under the tested worker configuration.

## Data-URI SVG nested-resource validation

The third advisory is a different validator-chain failure. Dompdf accepts a `data:image/svg+xml` resource, pre-parses it, and later hands it to `php-svg-lib` with external references enabled. The nested SVG `<image>` resolution does not inherit Dompdf's chroot decision. This is not the sibling-prefix bug: even a path with no shared chroot prefix may be reached if the nested resource is a supported image.

Use a disposable renderer with one distinctive image canary outside the configured render root:

1. Render a direct local image reference to the canary and confirm the chroot rejects it.
2. Create a minimal SVG whose only nested `<image>` reference points to that same canary. Encode the SVG as a data URI and place it in an outer HTML `<img>`.
3. Render once and inspect only whether the known canary pixels are embedded. Record the outer URI scheme, nested normalized path, Dompdf and `php-svg-lib` versions, and output hash.
4. Repeat with an in-root image, a nonexistent path, external references disabled in a local control, and Dompdf 3.1.6 or later.

Positive evidence is **outer data URI passes Dompdf validation -> nested SVG image is resolved by a second library without the chroot policy -> synthetic outside-root image appears in the PDF**. Do not probe text files, credentials, application config, user uploads, or arbitrary server paths. Keep the claim to image-readable local resources unless another file type is independently proven in the authorized lab.

Report the three paths separately: **raw-path prefix confinement**, **resource-existence side channel**, and **nested-parser policy loss**. They have different prerequisites and evidence.

The later [GHSA-j8qw-6jw8-r297](https://github.com/advisories/GHSA-j8qw-6jw8-r297) entry adds an explicit nested-SVG existence oracle. Reuse the same disposable renderer but compare only a synthetic file, synthetic directory, and definitely absent sibling under one temporary tree. Capture warning class, render status, elapsed time, and output hash; do not use sensitive example paths. Existing-path differences prove an oracle, not readable content, and must not be upgraded to arbitrary file disclosure without separate canary-content evidence.
