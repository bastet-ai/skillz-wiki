---
title: GitLab package-registry traversal and docker-socket-proxy read-endpoint boundaries
---

# GitLab package-registry traversal and docker-socket-proxy read-endpoint boundaries

Two 2026-08-23 GitHub advisories expose one durable operator pattern: a proxy, registry, or operator layer that re-implements path handling and permission gating on top of an authoritative backend (GitLab's package-registry storage, the Docker Engine API) and gets one side of the binding wrong. In GitLab, an authenticated user reaches a package-registry route whose storage path is built from user-supplied package coordinates, and on affected versions the traversal reaches code execution. In docker-socket-proxy, a read-endpoint allow-list is applied per namespace but misses the `/containers/{id}/archive` and `/containers/{id}/export` routes, so any caller who can talk to the proxy can read arbitrary container files and tar-download entire container filesystems, which on a host that runs sensitive workloads is a host-level information-disclosure and credential-theft primitive.

Source records:

- GitLab CE/EE package-registry path traversal leading to authenticated RCE, 18.8 < 19.0.6, 19.1 < 19.1.4, 19.2 < 19.2.2 (CWE-22, CVSS 8.5): [GHSA-2fpv-gqh2-qq5r](https://github.com/advisories/GHSA-2fpv-gqh2-qq5r);
- docker-socket-proxy insufficient endpoint gating on `CONTAINERS`-enabled reads: `GET /containers/{id}/archive`, `/export`, `/logs`, `/top` reachable without per-endpoint gating, enabling arbitrary file reads and full-filesystem tar downloads (CVSS 7.4): [GHSA-gxmj-gjp2-h2mv](https://github.com/advisories/GHSA-gxmj-gjp2-h2mv).

Confirm the exact GitLab major/patch, whether the package registry is enabled (`gitlab gem list` / `gitlab-rake gitlab:env:info` or the admin area), which registry storage backend (filesystem, S3, GCS) and where the registry root lives on the application host, and which API role the test identity holds. For docker-socket-proxy, confirm the `CONTAINERS`/allow-list environment variables, the proxy-to-socket mount, and which Docker clients or workloads share that socket.

!!! warning "Lab-only, synthetic packages, marker files, and denied sinks"
    Use a disposable GitLab install on an isolated host with a local registry storage root containing only synthetic marker files, and a disposable docker-socket-proxy with a lab Docker daemon running only throwaway containers whose filesystem contains only inert marker files. Never target a production registry, never pull or publish real package contents, never read real host files or workload credentials, and never install a package to trigger real execution.

## Boundary map

| Surface | Intended authority | Untrusted input | Bounded positive |
| --- | --- | --- | --- |
| GitLab package-registry API routes (upload/download/purge by project, package, version, file name) | authenticated user scoped to their projects/packages | project path, package name/version, and file-path segments in registry API URLs | a denied storage-recorder observes a read/write landing outside the registry storage root when registry coordinates encode traversal |
| docker-socket-proxy read namespace | namespace allow-list (`CONTAINERS`) | endpoint choice under `/containers/{id}/` plus `{id}` | `GET /containers/{id}/archive` or `/export` on an allowed namespace returns container-filesystem bytes (marker file content) while sibling gated endpoints 403 |

The finding in both cases is a **broken binding between the caller's scope and the storage or namespace the final sink actually addresses**, not the HTTP status. Capture the request coordinates, the scope decision, the canonical path or container target, and the sink decision separately.

## 1. GitLab package-registry path traversal

The advisory states the traversal sits in the package registry and yields RCE "under certain conditions" on 18.8 before 19.0.6, 19.1 before 19.1.4, and 19.2 before 19.2.2. The registry API accepts a project path, a package type, a version, and a filename; the storage layer resolves those into a filesystem or object path. If any segment (typically the version or filename) is not canonicalized before being joined to the registry root, a caller can point the final read/write outside the registry storage.

Replayable validation:

1. Stand up a disposable GitLab on the affected version with the package registry enabled and a local storage root that holds only inert marker files.
2. Instrument the storage layer's final path resolution (or the filesystem calls below it) with a recorder that captures the canonical target path and denies any operation that resolves outside the registry root.
3. Drive the registry API as a synthetic low-privilege user: enumerate the registry coordinate grammar (`/api/v4/projects/:id/packages/:pkg/...`) with crafted version and filename segments (encoded and literal traversal, double-encoding, `..` after an innocuous prefix, URL-escaped variants, and empty segments).
4. Compare against a control request with well-formed coordinates that stays inside the root.
5. Re-run the same request set against the fixed version and record the negative control.

A bounded positive is **attacker-chosen registry coordinate -> storage resolver -> canonical path outside the registry root observed by the denied recorder**, on the affected build only. The RCE claim additionally depends on what the out-of-root write or read hits (executable path, registry job scripts, CI variables), that is a separate untested precondition. Report the exact coordinate shape, the version, the storage backend, and the recorder capture; do not claim RCE from the traversal alone.

## 2. docker-socket-proxy read-endpoint gating differential

docker-socket-proxy's purpose is to let one Docker API surface reach the engine socket with a namespace allow-list. The `CONTAINERS` environment variable authorizes the `/containers` namespace. The advisory states the allow-list gates the namespace entry points but not the read sub-endpoints under it: with `CONTAINERS` set, `GET /containers/{id}/archive`, `/containers/{id}/export`, `/containers/{id}/logs`, and `/containers/{id}/top` are callable by any client of the proxy. `/archive` is Docker's own file-copy primitive; `/export` streams the whole container filesystem as a tar.

Replayable validation:

1. Run a disposable Docker daemon with one throwaway container whose filesystem contains only inert marker files (no secrets, no credentials, no real workload data).
2. Front it with docker-socket-proxy configured with `CONTAINERS` (or the equivalent read-namespace variable) as in the vulnerable configuration.
3. Send `GET /containers/{id}/archive?path=<marker>` and `GET /containers/{id}/export` to the proxy with the same caller that would 403 on a properly gated endpoint. Record the response status and the returned bytes hash.
4. Build the endpoint decision table: which of `/containers/{id}/archive|export|logs|top|exec|create|start|kill` is permitted versus denied under the active namespace variables, in both the affected and the fixed build.
5. Confirm the negative control: a proxy configured without the namespace variable denies every `/containers/*` read.

A bounded positive is **allowed-namespace read endpoint -> container filesystem bytes (marker file content or tar containing marker files) returned to a proxy client**, on the affected build only. On a real host this primitive exposes workload credentials, token files, and build context; in an assessment, report the endpoint decision table and the marker-file proof, and stop. Never use the proxy to read host or other-workload files, and never pair the read with an execution sink.

## Reporting heuristics

Lead with the crossed binding:

- **GitLab**: authenticated registry coordinate -> uncanonicalized storage path -> out-of-root read/write (CWE-22), version matrix 18.8/19.1/19.2 with fixed 19.0.6/19.1.4/19.2.2.
- **docker-socket-proxy**: namespace allow-list granted -> per-endpoint gate missing -> `archive`/`export` file reads and full-filesystem tar (CWE-1220 family: insufficiently controlled surface gating).

Strong reports include the exact coordinates or endpoint/method, the active allow-list/namespace variables, the canonical target the recorder observed, the fixed-version negative control, and a clear statement of what the read primitive implies on a real host (credential and workload-file exposure) without actually reading anything sensitive. Durable operator lesson: **when a middle layer re-implements scope on top of an authoritative backend, test both the entry gate and the final sink**, an allow-list that covers the namespace but not the leaf endpoint is the same bug as a traversal that covers the URL but not the path.

## Notes on skipped adjacent items

The same 2026-08-23 wave included a StackGres operator database-tenant-to-administrator privilege escalation (GHSA-gf36-c938-gjrw, sparse description, CWE-426), a Comfast CF-N1-S NTP CGI stack-overflow (GHSA-j397-vxh8-xhw3), Tenda CH22 command injection (GHSA-x5qw-fmv8-fhx9), CHIRP CSV eval injection (GHSA-6rmm-3cfr-7939), MeTube cookie-file disclosure (GHSA-hjhm-cmvf-w9vp), TaxHacker hard-coded-JWT-secret and IMAP SSRF pair (GHSA-c2p7-hcxm-xqhj, GHSA-hrrq-qh5p-23c2), Systerel S2OPC OOB read (GHSA-cq93-frxj-593v), strongSwan EAP-identity double-free (GHSA-55p5-7gvc-767j), and two CVE-rejected records (GHSA-fww7-qrfp-8vpv, GHSA-p2fw-9cp5-8w2c). These are product-specific records without a new reusable operator pattern in this window and are tracked to state without publication. The WordPress auth/registration/role records from the same wave are folded into the WordPress payment/device page as an August 23 follow-up.
