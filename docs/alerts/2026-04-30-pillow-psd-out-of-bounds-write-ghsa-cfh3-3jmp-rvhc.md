# Pillow PSD loader out-of-bounds write (GHSA-cfh3-3jmp-rvhc / CVE-2026-25990)

**Signal:** GitHub Security Advisories updated **2026-04-30**. Pillow disclosed an out-of-bounds write reachable while loading crafted PSD images.

## What it is
Pillow versions `10.3.0` through `12.1.0` can trigger an out-of-bounds write when parsing a specially crafted Photoshop PSD image. Any service that accepts user-supplied images and calls `Image.open()` or similar decoding paths on PSD content should treat this as a memory-corruption risk until patched or PSD decoding is disabled.

Affected package: PyPI `pillow` `>= 10.3.0, < 12.1.1`. Fixed version: `12.1.1` when available.

Reference: <https://github.com/advisories/GHSA-cfh3-3jmp-rvhc>

## Triage
1. Inventory Python services, workers, CI pipelines, and media processors that use Pillow on untrusted uploads.
2. Check whether PSD files are accepted directly, via content sniffing, or through archive/document extraction pipelines.
3. Identify high-risk contexts: thumbnailers running with broad filesystem access, multi-tenant media conversion, async job queues, and privileged desktop automation.
4. Review recent crashes, worker restarts, sanitizer failures, or unusual PSD uploads.

## Mitigation
- Upgrade Pillow to `12.1.1` or later once released for your platform.
- Until patched, block PSD uploads or call `Image.open(..., formats=[...])` with PSD excluded.
- Decode untrusted images in a sandboxed, low-privilege worker with CPU/memory/time limits and no access to secrets.
- Validate file type allowlists before decoding; do not rely on file extensions alone.

## Detection ideas
- Alert on PSD uploads to services that historically only needed web image formats.
- Monitor thumbnailer and media-worker crashes correlated with PSD parsing.
- Preserve suspicious input files for offline triage in an isolated environment.

## Durable lesson
Image parsers are attack surfaces, not utilities. If a workflow only needs JPEG/PNG/WebP, constrain decoder formats explicitly and run unavoidable parsing in a sandbox.
