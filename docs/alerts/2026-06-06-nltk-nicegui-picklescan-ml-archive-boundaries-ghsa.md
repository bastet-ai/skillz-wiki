# NLTK, NiceGUI, Picklescan, and ML archive-boundary checks

Source: GitHub Security Advisories REST API, updated 2026-06-06.

This batch is durable because it turns an updated-advisory wave into reusable offensive validation patterns for **trusted archive extraction**, **client-controlled upload filenames**, **ML model scanner bypasses**, and **model/test-data archive writes**. Use these workflows only in authorized labs, staging systems, or explicitly scoped assessments.

## What changed

- **NLTK downloader ZIP extraction**, [GHSA-7p94-766c-hgjp](https://github.com/advisories/GHSA-7p94-766c-hgjp) / CVE-2025-14009: the NLTK downloader's `_unzip_iter` used `zipfile.extractall()` without path validation, so malicious NLTK packages can write outside the extraction root; attacker-supplied Python package files can become code execution when later imported.
- **NiceGUI upload filename traversal footgun**, [GHSA-9ffm-fxg3-xrhh](https://github.com/advisories/GHSA-9ffm-fxg3-xrhh) / CVE-2026-25732: `FileUpload.name` exposes client-supplied filename metadata, and `SmallFileUpload.save()` / `LargeFileUpload.save()` accept caller-provided paths. Apps using patterns such as `UPLOAD_DIR / e.file.name` can write outside the intended upload directory.
- **Picklescan scanner-bypass family**, [GHSA-jgw4-cr84-mqxg](https://github.com/advisories/GHSA-jgw4-cr84-mqxg) / CVE-2025-10155, [GHSA-mjqp-26hc-grxg](https://github.com/advisories/GHSA-mjqp-26hc-grxg) / CVE-2025-10156, and [GHSA-f7qq-56ww-84cr](https://github.com/advisories/GHSA-f7qq-56ww-84cr) / CVE-2025-10157: updated advisories describe scanner bypasses through extension mismatch, ZIP CRC handling differences, and unsafe-global matching gaps for subclass imports.
- **ML archive extraction writes**, [GHSA-x6ww-pf9m-m73m](https://github.com/advisories/GHSA-x6ww-pf9m-m73m) / CVE-2025-58755 and [GHSA-6rq9-53c3-f7vj](https://github.com/advisories/GHSA-6rq9-53c3-f7vj) / CVE-2024-5187: MONAI bundle download/extraction and ONNX `download_model_with_test_data` paths used archive extraction patterns that can write outside the expected output directory when processing malicious ZIP/TAR content.

## Operator triage

1. Search code, notebooks, CI jobs, model pipelines, and admin utilities for archive and upload sinks, not just package names:
   - `nltk.download(`, `Downloader`, `_unzip_iter`, and mirrors or private NLTK package indexes;
   - NiceGUI upload handlers using `e.file.name`, `file.name`, `.save(`, `UPLOAD_DIR /`, or `Path(...) / uploaded_name`;
   - `picklescan` gates in model-ingestion workflows, Hugging Face mirror checks, artifact quarantine jobs, or CI policy checks;
   - `monai.bundle.scripts.download`, MONAI bundle imports, `zip_file.extractall`, ONNX `download_model_with_test_data`, and model-test-data TAR/ZIP ingestion.
2. Prioritize shared ML platforms, internal model hubs, notebook gateways, and admin upload tools where lower-privileged users can supply archives, model artifacts, or filenames that a more privileged runtime later extracts or loads.
3. Treat scanner success as a signal, not proof of safety. A durable finding often shows a differential: the scanner returns clean/error/no result while the downstream loader still accepts or reaches the artifact.
4. For archive writes, prove containment failure only with disposable marker paths under a lab-owned directory. Do not overwrite application source, SSH keys, cron paths, startup scripts, service configs, or production model files.
5. For upload filename traversal, report the vulnerable application pattern. NiceGUI's primitive becomes exploitable when app code trusts `file.name` while building save paths.

## Replayable validation boundaries

### Archive extraction path-containment canary

Use for NLTK package downloads, MONAI bundles, ONNX model test-data archives, and similar extraction helpers.

1. Create a throwaway extraction root and a separate lab marker target, for example `/tmp/skillz-archive-target/marker.txt`.
2. Build a ZIP or TAR in a lab with one normal file and one traversal or absolute-path entry that targets the marker location. Keep the payload content to a unique non-secret string.
3. Exercise the exact application extraction path with the crafted archive through the same interface a real user controls: downloader mirror, bundle URL, model import, or test-data helper.
4. Vulnerable result: the marker appears outside the intended extraction root, or an error/log proves the helper attempted to write the out-of-root path.
5. Capture package version, extraction helper, archive member path, intended root, actual marker path, and the request/import path. Remove the marker after validation.

### NiceGUI upload filename traversal canary

Use two requests in a staging app or lab clone that contains the suspected upload handler.

1. Confirm the handler saves uploaded files with a path derived from `e.file.name` or equivalent client-controlled metadata.
2. Upload a harmless file whose filename contains a traversal sequence targeting a disposable directory, for example `../skillz-upload-marker.txt` relative to the configured upload root.
3. Vulnerable result: the marker file is created outside the upload root, or logs show the app attempted an out-of-root write.
4. Capture the handler code pattern, authenticated role, filename supplied on the wire, upload root, resulting file path, and whether generated/sanitized filenames would block the issue.
5. Do not target executable application paths, template directories, cron jobs, keys, or config files during validation.

### Picklescan differential scanner-bypass canaries

Run only against inert artifacts in a throwaway sandbox without credentials.

1. Create or obtain benign pickle artifacts that exercise the same structural bypass classes without malicious side effects:
   - a standard pickle renamed with a PyTorch-like extension such as `.bin`;
   - a ZIP-style model artifact with a CRC mismatch on a contained pickle-like member;
   - a pickle referencing a dangerous-family subclass/import shape that should be considered unsafe by policy.
2. Scan each artifact with the exact Picklescan version and flags used by the target pipeline.
3. Exercise the downstream loader only in a sandbox and only far enough to prove the loader still accepts or attempts to process the artifact class.
4. Vulnerable result: Picklescan reports clean/error/no result while the downstream loader accepts the artifact or reaches the canary import/member.
5. Capture scanner version, flags, artifact extension, archive metadata, scan output, loader behavior, and the policy expectation. Do not publish weaponized pickle payloads.

## August 3 follow-up: verify NLTK package bytes before writing or extracting

[GHSA-pv39-qrfq-g8gc / CVE-2026-12259](https://github.com/advisories/GHSA-pv39-qrfq-g8gc) adds a different NLTK downloader boundary. In NLTK 3.9.4, `Downloader._download_package()` can write downloaded bytes and extract them before enforcing the package metadata's SHA-256 or MD5 checksum. This is not the earlier archive-member traversal issue: the package may remain inside the intended directory while the downloader installs bytes whose expected digest has not yet been authenticated.

### Owned-mirror write-order harness

1. Use an isolated NLTK data directory, an owned local HTTP mirror, a synthetic package index entry, and a tiny corpus ZIP containing only marker text. Block all other outbound networking.
2. Serve three bodies for the same synthetic package metadata: the expected body, a one-byte-modified body with the original digest, and a truncated body. Keep archive member names confined to the NLTK data root.
3. Interpose recorders around package-file creation, extraction, digest computation, installed-status mutation, and downstream corpus lookup. The recorders may write only inside the disposable data directory.
4. For each body, record the event sequence rather than only the final exception: **response complete -> digest decision -> package write -> extraction -> index/status update -> downstream lookup**.
5. Affected evidence is that the mismatched body reaches package write, extraction, installed state, or downstream selection before checksum rejection. A network response or temporary in-memory buffer before verification is not by itself a finding.
6. Repeat against the corrected build. Require a cryptographic digest decision over the complete response before any persistent package replacement, extraction, installed-state update, or consumer-visible lookup.
7. Remove the disposable data root and verify that no package path, environment variable, or notebook configuration points at it afterward.

The bounded positive is **owned mirror substitutes an inert mismatched package -> affected downloader writes or extracts it before reporting checksum failure -> patched downloader rejects before the first persistent or consumer-visible side effect**. Do not place Python modules, pickle files, startup hooks, or executable content in the package, and do not infer code execution from marker installation alone.

Report the two NLTK checks separately: archive path traversal asks **where an authenticated package member is written**, while this issue asks **whether the package body is authenticated before any write or extraction**. A strong pipeline tests both ordering and containment.

## Reporting heuristics

- Frame NLTK, MONAI, and ONNX findings as **trusted archive extraction crossing a filesystem boundary**. Strong reports name the user-controlled archive source and the higher-privileged extraction identity.
- For NLTK package-integrity findings, preserve the exact side-effect order and identify the controlled mirror, proxy, or source-substitution precondition. A checksum error after extraction is positive evidence; a checksum error before all persistent effects is the expected control.
- Frame NiceGUI findings as **client-supplied filename metadata consumed by app code**. Include a minimal code path or route that constructs a filesystem path from `file.name`.
- Frame Picklescan findings as **scanner/loader differential bypasses**. The impact is strongest where scanner output gates ingestion into a model hub, CI release, notebook runtime, or production ML job.
- Separate path write from code execution. Code execution requires a credible follow-on load/import/startup path; otherwise report the arbitrary write primitive and its reachable file classes.
- The same updated-feed wave included orjson recursion and legacy Plone identity/CSRF items; those were reviewed but not promoted here because they are availability-only, old/generic identity issues, or lacked a distinct durable operator workflow for this wiki.

## Sources

- GitHub Advisory Database: [GHSA-7p94-766c-hgjp / CVE-2025-14009](https://github.com/advisories/GHSA-7p94-766c-hgjp)
- NLTK advisory/source: <https://github.com/nltk/nltk/security/advisories> and <https://github.com/nltk/nltk>
- GitHub Advisory Database: [GHSA-pv39-qrfq-g8gc / CVE-2026-12259](https://github.com/advisories/GHSA-pv39-qrfq-g8gc)
- GitHub Advisory Database: [GHSA-9ffm-fxg3-xrhh / CVE-2026-25732](https://github.com/advisories/GHSA-9ffm-fxg3-xrhh)
- NiceGUI advisory/source: <https://github.com/zauberzeug/nicegui/security/advisories> and <https://github.com/zauberzeug/nicegui>
- GitHub Advisory Database: [GHSA-jgw4-cr84-mqxg / CVE-2025-10155](https://github.com/advisories/GHSA-jgw4-cr84-mqxg)
- GitHub Advisory Database: [GHSA-mjqp-26hc-grxg / CVE-2025-10156](https://github.com/advisories/GHSA-mjqp-26hc-grxg)
- GitHub Advisory Database: [GHSA-f7qq-56ww-84cr / CVE-2025-10157](https://github.com/advisories/GHSA-f7qq-56ww-84cr)
- Picklescan advisory/source: <https://github.com/mmaitre314/picklescan/security/advisories> and <https://github.com/mmaitre314/picklescan>
- GitHub Advisory Database: [GHSA-x6ww-pf9m-m73m / CVE-2025-58755](https://github.com/advisories/GHSA-x6ww-pf9m-m73m)
- MONAI advisory/source: <https://github.com/Project-MONAI/MONAI/security/advisories> and <https://github.com/Project-MONAI/MONAI>
- GitHub Advisory Database: [GHSA-6rq9-53c3-f7vj / CVE-2024-5187](https://github.com/advisories/GHSA-6rq9-53c3-f7vj)
- ONNX source/issues: <https://github.com/onnx/onnx> and <https://github.com/onnx/onnx/issues/6215>
