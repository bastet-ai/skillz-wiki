# File-write and install-path escape batch, operator validation

**Date reviewed:** 2026-08-27  
**Advisories:**
- [GHSA-f63g-88cj-hjf9](https://github.com/advisories/GHSA-f63g-88cj-hjf9) / CVE-2026-54550, IzPack unpacker path traversal (high)
- [GHSA-gmxc-r82q-347r](https://github.com/advisories/GHSA-gmxc-r82q-347r) / CVE-2026-54732, `libreoffice-convert` filename path traversal / arbitrary file write (medium)
- [GHSA-q7m3-rhxg-7vxr](https://github.com/advisories/GHSA-q7m3-rhxg-7vxr) / CVE-2026-54687, `n8n-nodes-sqlite3` `db_path` path traversal (medium)
- [GHSA-mf7q-r4rv-jv94](https://github.com/advisories/GHSA-mf7q-r4rv-jv94), Crossplane cosign verify-then-fetch TOCTOU (high)

**Boundary class:** caller-supplied filenames / paths / references that are joined to a working directory or resolved twice, escaping an install root, a temp dir, or a signature boundary.

## What is durable here

Three of these are the same recurring primitive from three different surfaces:
**a caller-supplied name or path is concatenated or resolved without a
containment check, so the write/read target escapes the intended root.** The
fourth (Crossplane) is a variant on the *supply-chain* version of the same
idea: a name that is resolved once for verification and a second, independent
time for fetch, so "verified" and "fetched" can refer to different content.

| Advisory | Surface | Transition | Root the escape crosses |
| --- | --- | --- | --- |
| [GHSA-f63g-88cj-hjf9](https://github.com/advisories/GHSA-f63g-88cj-hjf9) / CVE-2026-54550 | IzPack installer, `UnpackerBase.unpack()` (≤ 5.2.6) | trojanized pack entry `targetPath` with `../` | install dir → attacker-chosen path (startup folder, PATH dir, system location) under victim privileges |
| [GHSA-gmxc-r82q-347r](https://github.com/advisories/GHSA-gmxc-r82q-347r) / CVE-2026-54732 | `libreoffice-convert` < 1.8.2, `options.fileName` | `path.join(tempDir.name, fileName)` without `path.basename` | temp dir → arbitrary writable path (`~/.ssh/authorized_keys`, `/etc/cron.d`, web root) |
| [GHSA-q7m3-rhxg-7vxr](https://github.com/advisories/GHSA-q7m3-rhxg-7vxr) / CVE-2026-54687 | `n8n-nodes-sqlite3` < 1.0.0, `db_path` | untrusted input wired to the node's `db_path` parameter | workflow sandbox → arbitrary SQLite-openable file read/overwrite under the n8n process |
| [GHSA-mf7q-r4rv-jv94](https://github.com/advisories/GHSA-mf7q-r4rv-jv94) | Crossplane `crossplane-runtime/v2` `2.4.0-rc.0` | tag reference resolved separately for cosign verify and for fetch | signature boundary → unsigned image installed after a signed one was verified (TOCTOU) |

The operator value is the **containment-check review pattern** applied to any
"filename joins a directory" or "name resolves to an artifact" transition:

1. **Filename + directory join**, does the code reduce the filename to a base
   name (`path.basename` / `filepath.Base`) before `join`? If not, `../` in the
   name escapes the directory.
2. **Pack/entry `targetPath`**, installer and archive formats that carry a
   per-entry destination path are a classic escape vector when the entry path
   is attacker-controlled (trojanized media) and there is no
   canonicalization/containment check.
3. **Parameter that names a file**, a node/plugin parameter like `db_path`
   that a *trusted author* can wire to *untrusted input* converts a
   configuration choice into an arbitrary-file primitive in multi-tenant
   deployments.
4. **Verify-then-fetch by name**, if a registry reference (tag) is resolved
   independently for signature verification and for pull, a tag can point at a
   signed image during verify and an unsigned one during fetch. The
   "verified" claim is not bound to the fetched artifact.

## Recon

- **IzPack:** identify `izpack-installer` version (≤ 5.2.6 in range). The
  pack format is unsigned, so a trojanized `.jar` is the delivery. This is a
  *victim-runs-the-installer* chain, not a remote service.
- **libreoffice-convert:** identify the Node `libreoffice-convert` version in
  the app (< 1.8.2 in range) and whether `options.fileName` is ever derived
  from user input (upload filename, remote name).
- **n8n-sqlite3:** identify the node version (< 1.0.0 in range) and whether the
  deployment is multi-tenant / user-facing with untrusted workflow authors.
- **Crossplane:** identify `crossplane-runtime/v2` = 2.4.0-rc.0 and whether
  `ImageConfig` signature verification is enabled *and* packages are installed
  by tag rather than digest.

## Validation workflow (authorized lab / customer-approved)

All four proofs stop at the **destination differential**, "the target left the
intended root / the fetched artifact ≠ the verified artifact", and do not
complete a write to a real protected path, a SQLite overwrite of a real DB, or
an unsigned install on a cluster.

### IzPack unpacker escape
- Build a lab IzPack 5.2.6 installer whose pack contains one entry whose
  `targetPath` is `<install>/../canary.txt`. Run it on an isolated VM.
- Secure result: entry confined to the install dir. Vulnerable result:
  `canary.txt` present as a sibling of the install dir. Record the path, do not
  write to startup/PATH/system paths.

### libreoffice-convert filename escape
- In an isolated Node process, call `libreoffice-convert` with
  `options.fileName = ../../canary.txt` and a small document buffer.
- Secure result (1.8.2): file written as `canary.txt` inside the temp dir
  (`path.basename`). Vulnerable result (< 1.8.2): file written two levels up.
- Do not point the escape at `~/.ssh`, `/etc/cron.d`, or a live web root.

### n8n-sqlite3 `db_path`
- On a disposable n8n instance, create a workflow where `db_path` is wired to
  an input field. Feed a path that names a **disposable** SQLite file outside
  the workflow's working dir. Secure result (1.0.0): the node refuses or
  confines. Vulnerable result: SQLite opens the named file. Do not open a real
  application database.

### Crossplane cosign TOCTOU
- On an isolated registry + cluster with `ImageConfig` verification enabled and
  Kyverno-style install by tag, have the registry serve a correctly signed
  image for the verify step and a different (unsigned) image for the fetch step
  under the same tag. Secure result (2.4.0-rc.1): install refused or the
  digest is pinned so both steps resolve the same artifact. Vulnerable result
  (2.4.0-rc.0): unsigned image installed. Keep the "unsigned" image inert.

## Reporting heuristic

- Name the exact join/resolve function and the exact unvalidated field
  (`targetPath`, `options.fileName`, `db_path`, tag-reference resolve).
- For the three path escapes, the finding is *root escape*, proven by a marker
  file landing outside the intended directory. For Crossplane, the finding is
  *signature-boundary TOCTOU*, proven by the verified-vs-fetched artifact
  differential.
- Do not publish the trojanized pack, the `../` filename payload used on a
  production host, or the unsigned image used on a live cluster.

## Safety constraints

- No write to `~/.ssh`, `/etc`, PATH directories, startup folders, or a live
  web root.
- No overwrite of a real SQLite/application database.
- No unsigned package install on a shared or customer cluster.
- Use isolated VMs / disposable clusters and marker files only.
