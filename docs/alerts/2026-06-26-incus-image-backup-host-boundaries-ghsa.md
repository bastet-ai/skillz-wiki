# Incus image, backup, and object-storage host-boundary checks

Source: hourly offensive-security scan, 2026-06-26. Primary entries: GitHub Advisory Database [GHSA-2q3f-q5pq-g8wv](https://github.com/advisories/GHSA-2q3f-q5pq-g8wv) / CVE-2026-48749, [GHSA-73hr-m85f-64v9](https://github.com/advisories/GHSA-73hr-m85f-64v9) / CVE-2026-48750, [GHSA-48q5-w887-33wv](https://github.com/advisories/GHSA-48q5-w887-33wv) / CVE-2026-48751, [GHSA-vxp5-584q-c479](https://github.com/advisories/GHSA-vxp5-584q-c479) / CVE-2026-48752, [GHSA-ccjc-4qc3-jxqc](https://github.com/advisories/GHSA-ccjc-4qc3-jxqc) / CVE-2026-48753, [GHSA-v6mj-8pf4-hhw4](https://github.com/advisories/GHSA-v6mj-8pf4-hhw4) / CVE-2026-48755, and [GHSA-f6m5-xw2g-xc4x](https://github.com/advisories/GHSA-f6m5-xw2g-xc4x) / CVE-2026-48769. Adjacent nil-pointer Incus issues [GHSA-4xg6-52mh-fpw8](https://github.com/advisories/GHSA-4xg6-52mh-fpw8) / CVE-2026-48754 and [GHSA-xhqx-mgh3-3h7q](https://github.com/advisories/GHSA-xhqx-mgh3-3h7q) / CVE-2026-48756 were reviewed but are not promoted beyond grouping context because they are availability-only.

This cluster is durable for operators because it exposes repeatable container control-plane boundaries: untrusted image metadata, rootfs/templates/exec-output filesystem entries, backup descriptors, S3 multipart object keys, compression algorithm names, and restricted-project settings crossing into host file reads/writes or command execution.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-2q3f-q5pq-g8wv](https://github.com/advisories/GHSA-2q3f-q5pq-g8wv) / CVE-2026-48749 | Incus image import / rootfs handling | malicious image `rootfs/` symlink handling could cross from image content into host file read/write | Add image-root symlink canaries to container-platform import tests; evidence should stop at disposable host marker files. |
| [GHSA-73hr-m85f-64v9](https://github.com/advisories/GHSA-73hr-m85f-64v9) / CVE-2026-48750 | Incus image execution-output handling | crafted image `exec-output` symlinks could redirect host-side writes | Test generated-output paths separately from rootfs extraction; prove with marker-only temp directories. |
| [GHSA-vxp5-584q-c479](https://github.com/advisories/GHSA-vxp5-584q-c479) / CVE-2026-48752 | Incus image templates | image-controlled `templates/` symlinks could become arbitrary host file read/write primitives | Treat template expansion as a host-filesystem sink, not just guest initialization metadata. |
| [GHSA-48q5-w887-33wv](https://github.com/advisories/GHSA-48q5-w887-33wv) / CVE-2026-48751 | Incus restricted projects | restricted-project assumptions could be bypassed into command execution | Validate project restrictions with a route/setting matrix and inert command markers in a throwaway project only. |
| [GHSA-ccjc-4qc3-jxqc](https://github.com/advisories/GHSA-ccjc-4qc3-jxqc) / CVE-2026-48753 | Incus S3-compatible multipart upload | object names or multipart state could traverse outside the intended storage root | Include S3/object-storage upload paths in filesystem-boundary reviews for container platforms. |
| [GHSA-v6mj-8pf4-hhw4](https://github.com/advisories/GHSA-v6mj-8pf4-hhw4) / CVE-2026-48755 | Incus backup import/compression | backup compression algorithm selection could cross into argument injection, arbitrary file write, and command execution | Treat archive/backup metadata fields as command-line construction inputs; prove only with inert compressor names and temp output paths. |
| [GHSA-f6m5-xw2g-xc4x](https://github.com/advisories/GHSA-f6m5-xw2g-xc4x) / CVE-2026-48769 | Incus client image trust | trusted image hashes could still lead the client into arbitrary file writes | Client-side image handling belongs in scope when operators import images from registries, projects, or handoff artifacts. |

## Operator triage

1. **Map every host-write sink before building canaries.** Image import, template expansion, exec output, backup restore, S3 multipart upload, and client-side image unpacking may each normalize paths differently.
2. **Separate server, client, and project-boundary findings.** Incus daemon host writes, local client writes, and restricted-project escapes have different evidence and authorization requirements.
3. **Prefer synthetic host markers.** Use temp directories, unique marker filenames, and throwaway projects. The proof is path escape or inert command reachability, not reading sensitive files.
4. **Check symlinks in every image-controlled directory.** `rootfs/`, `templates/`, generated-output directories, backup metadata, and storage-driver staging directories should all have explicit symlink/canonicalization tests.
5. **Record negative controls.** Include patched Incus version, project restriction settings, rootless/rootful mode, storage backend, S3 API exposure, and whether imports came from image, backup, or client workflow.

## Replayable validation boundaries

### Image symlink and template harness

- Preconditions: disposable Incus lab host, throwaway project, no production containers, a temp host canary directory such as `/tmp/skillz-incus-canary/`, and explicit approval to import crafted images.
- Build or obtain only a minimal lab image whose `rootfs/`, `templates/`, and output-related entries contain symlinks that point to the temp canary directory.
- Import and launch the image through the exact path in scope: local image import, remote image server, project-scoped import, or client-side image handling.
- Evidence should be a table of attempted path, normalized host path, marker filename, operation type, Incus version, project settings, and fixed-version result.
- Do not point symlinks at `/etc`, `/root`, service config, images owned by other tenants, cloud credentials, SSH keys, databases, or real container volumes.

### Backup and compression metadata harness

- Preconditions: isolated lab instance, disposable backup archives, temp extraction/output roots, and inert marker strings for algorithm or option fields.
- Create paired backups where only the compression/metadata field or path-like field changes from a valid baseline to a harmless canary.
- Restore or inspect the backup in a controlled project and capture whether the canary reaches process arguments, output filenames, or host paths.
- Positive evidence is an argument-boundary log, marker file in a temp directory, or rejected patched result. Stop before command execution payloads, shell metacharacters that run real commands, or writes outside the canary root.

### S3 multipart storage-root harness

- Preconditions: lab Incus object-storage/S3-compatible endpoint, disposable bucket or project, and an owned callback/storage backend if external services are used.
- Upload multipart objects with baseline names, normalized separator variants, and traversal-looking marker names that should remain confined to the storage root.
- Verify only marker object presence, filesystem path logs, or storage backend path decisions. Do not enumerate unrelated buckets, tenant objects, or backend credentials.

### Restricted-project command-boundary harness

- Preconditions: a throwaway restricted project, non-admin test user, inert command marker such as printing a fixed string, and no host mounts or privileged devices outside scope.
- Build a setting matrix for the restricted project: allowed images, profiles, devices, security flags, storage pools, and API routes reachable by the test user.
- Attempt only the documented workflow needed to show whether project restrictions can be bypassed into a canary command or unauthorized host-affecting operation.
- Evidence should show request/route, project setting, expected denial, observed action, marker output, and patched denial.

## Reporting notes

- Lead with the precise boundary: **image `rootfs/` symlink to host file**, **image `templates/` symlink to host file**, **exec-output symlink to host write**, **restricted project to command execution**, **multipart object key to storage-root traversal**, **backup compression metadata to command arguments**, or **trusted image hash to client file write**.
- Include Incus version, client/server split, storage backend, project restriction settings, import path, canary path, and negative control.
- Keep all artifacts synthetic and redacted. Do not publish payloads that overwrite host config, read secrets, escape into tenant data, or execute production commands.
