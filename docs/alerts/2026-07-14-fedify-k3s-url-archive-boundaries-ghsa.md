# Fedify SSRF canonicalization and K3s snapshot archive-boundary checks

Source: hourly offensive-security scan, 2026-07-14 GitHub advisory wave. Primary entries: [GHSA-xw9q-2mv6-9fr8](https://github.com/advisories/GHSA-xw9q-2mv6-9fr8) / CVE-2026-50131 and [GHSA-jxr7-mqhw-9p98](https://github.com/advisories/GHSA-jxr7-mqhw-9p98) / CVE-2026-54250.

This batch is durable because both advisories expose reusable operator checks: a federated-server URL guard that rejects common private IPv4 ranges but still permits other special-use IPv4 destinations before outbound ActivityPub/document/media fetches, and a Kubernetes distribution restore workflow that treats compressed etcd snapshots as trusted ZIP archives before writing extracted members to disk.

!!! warning "Authorized validation only"
    Keep proofs to isolated Fedify-compatible federation labs, owned callback domains, local URL-validator harnesses, disposable K3s clusters, synthetic etcd snapshots, and temporary canary files. Do not query cloud metadata, internal production services, third-party federation instances, real private feeds, production clusters, real etcd backups, service-account tokens, kubeconfigs, node credentials, or filesystem paths outside an approved lab.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-xw9q-2mv6-9fr8](https://github.com/advisories/GHSA-xw9q-2mv6-9fr8) / CVE-2026-50131 | Fedify `validatePublicUrl()` / `isValidPublicIPv4Address()` | SSRF mitigation blocks common private/local ranges but allows other special-use IPv4 ranges before runtime fetches | Expand URL-guard test matrices beyond `10/8`, `127/8`, `169.254/16`, `172.16/12`, and `192.168/16`; include reserved, benchmarking, multicast, documentation, shared-address, and transition ranges. |
| [GHSA-jxr7-mqhw-9p98](https://github.com/advisories/GHSA-jxr7-mqhw-9p98) / CVE-2026-54250 | K3s compressed etcd snapshot restore | ZIP member names can traverse out of the intended restore extraction root during admin-initiated snapshot decompression | Treat backup/restore archive handling as a privileged filesystem sink; prove only with disposable clusters and marker files. |

## Replayable validation boundaries

### Fedify special-use IPv4 SSRF guard bypass

1. Build a local harness around the exact Fedify version and the same URL validation path used before runtime document/media fetches. If testing an app built on Fedify, instrument the app-level fetch path as well as `validatePublicUrl()`.
2. Use only owned callback hosts and synthetic lab listeners. For blocked-address controls, use local harness decisions or lab-local canaries rather than real metadata or internal services.
3. Test address families in a table, not as one-off payloads:
   - common private/local controls: `10.0.0.1`, `127.0.0.1`, `169.254.169.254`, `172.16.0.1`, `192.168.0.1`;
   - special-use ranges commonly missed by allow/deny logic: `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, and `240.0.0.0/4`;
   - parser variants: integer IPv4, octal/hex-looking labels if the runtime accepts them, userinfo, redirects, trailing dots, DNS CNAMEs, and IPv4-mapped IPv6 forms.
4. Record `raw URL`, `parsed hostname`, `resolved address`, `validator decision`, `outbound client decision`, and `observed callback/denial`.
5. Add negative controls where a patched validator rejects every non-global destination before the outbound client runs.

Report this as **federation URL -> incomplete special-use IP classification -> server-side fetch past SSRF guard**. Evidence should be validator/callback decision tables; do not fetch production private resources.

### K3s compressed snapshot archive traversal

1. Stand up a disposable single-node K3s lab with no production workloads, secrets, or kubeconfigs. Use a temporary restore directory and a throwaway filesystem canary outside the intended extraction root.
2. Create or obtain a synthetic etcd snapshot ZIP containing harmless member names only, then add a traversal-shaped member name that targets a lab marker path such as a temporary directory under `/tmp/k3s-restore-canary/`.
3. Run only the documented restore path in the lab and observe whether decompression writes the marker outside the intended snapshot extraction directory. Do not target `/etc`, kubelet directories, manifests, service account paths, or shell startup files.
4. Repeat with patched behavior or with Go ZIP insecure-path protections enabled, and confirm the same archive is rejected or the traversal member is not written.
5. Preserve an archive listing, restore command, expected extraction root, observed marker path, and patched negative-control result.

Report this as **admin-supplied compressed etcd snapshot -> ZIP member pathname -> node filesystem write outside restore root**. Keep impact statements bounded to restore-time trust and do not imply unauthenticated cluster compromise.

## Reporting notes

- Lead with reachability and preconditions: Fedify runtime fetch path, URL guard version, allowed federation/media input source, K3s version, restore role, restore command, and whether the input archive is controlled by the tester.
- Prefer compact decision tables over payload dumps.
- Redact callback tokens, cluster paths that reveal sensitive topology, kubeconfig details, node hostnames from real environments, and any backup metadata not created for the lab.
- The same advisory wave included MKP pod-log memory exhaustion, Hoverfly denial-of-service issues, Wasmtime memory leak, and FacturaScripts stored XSS. Those were marked processed but not promoted because this run did not identify a non-availability or non-generic operator workflow beyond existing wiki coverage.
