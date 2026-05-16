# Cluster control-plane secret and impersonation boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where Kubernetes/GitOps control planes and container agents crossed secret, identity, and filesystem boundaries.

## Advisories covered

- **Argo CD ServerSideDiff Kubernetes Secret extraction** — [GHSA-3v3m-wc6v-x4x3](https://github.com/advisories/GHSA-3v3m-wc6v-x4x3): diff/render functionality can become a read path for Secrets when it runs with broader cluster privileges than the requesting principal.
- **Fleet Helm impersonation bypass** — [GHSA-765j-qfrp-hm3j](https://github.com/advisories/GHSA-765j-qfrp-hm3j): template rendering retained a `cluster-admin` REST client despite intended impersonation boundaries.
- **Rancher Extensions path traversal** — [GHSA-5v3h-x4wf-5c35](https://github.com/advisories/GHSA-5v3h-x4wf-5c35) / CVE-2026-25705: a malicious `UIPlugin` can abuse `compressedEndpoint` path traversal and Cluster Repo icon paths unless Rancher forces all resolved files to stay inside the extension cache/repository root.
- **Amazon ECS Container Agent for Windows information disclosure** — [GHSA-fc67-c4hg-q653](https://github.com/advisories/GHSA-fc67-c4hg-q653): host/container metadata boundaries can leak sensitive operational data when agent paths are exposed too broadly.

## Why this is durable

GitOps and container control planes are high-trust automation engines. Any helper that renders templates, computes diffs, loads extensions, or exposes agent state must execute as the requester, not as the operator's most privileged service account.

## Immediate triage

1. Patch Argo CD, Fleet, Rancher, and ECS Windows agents where present; prioritize shared clusters and internet-reachable management planes.
2. Review Argo CD ServerSideDiff usage and disable or restrict it for untrusted projects until patched.
3. Hunt for reads of Kubernetes Secret objects through diff/render endpoints and audit `impersonate` headers or service-account usage during Helm rendering.
4. Patch Rancher extension-capable managers to fixed trains: 2.14.1, 2.13.5, 2.12.9, or 2.11.13. Treat extension deployment rights as admin-equivalent until patched.
5. Inventory Rancher `UIPlugin` and Cluster Repo sources; remove unknown, writable, tenant-supplied, or non-vendor extension roots, and review extension install history for writes outside the cache/repository directory.
6. On Windows ECS hosts, review agent exposure, local access paths, and logs for unexpected metadata reads.

## Durable controls

- Enforce requester-scoped authorization at every render, diff, dry-run, and extension-read boundary.
- Use separate low-privilege service accounts for template/diff helpers; never reuse reconciler `cluster-admin` credentials for preview operations.
- Canonicalize extension file paths after decoding and symlink resolution, reject `../` before extraction, and verify `compressedEndpoint` artifacts and repo icons remain under immutable package/cache roots.
- Treat host agents as privileged daemons: bind locally, limit ACLs, redact metadata, and monitor unexpected local callers.
