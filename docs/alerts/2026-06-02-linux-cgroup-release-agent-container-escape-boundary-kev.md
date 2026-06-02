# Linux cgroup v1 `release_agent` container-escape boundary

Sources: CISA KEV catalog `2026.06.02` added [CVE-2022-0492 in the KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). The CVE is corroborated by the [NVD API record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492), the [CVE Program API record](https://cveawg.mitre.org/api/cve/CVE-2022-0492), and the upstream Linux kernel fix [commit `24f6008564183aa120d07c03d9289519c2fe02af`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24f6008564183aa120d07c03d9289519c2fe02af).

This is durable for operators because the bug class is not just an old kernel CVE. It gives a reusable container-assessment question: can a workload principal combine an affected kernel, cgroup v1 `release_agent`, writable cgroup control files, and elevated container capabilities into a namespace-isolation bypass?

## What changed

- **CISA KEV signal** — CISA added CVE-2022-0492 to the known-exploited catalog on 2026-06-02.
- **Vulnerable primitive** — NVD describes `cgroup_release_agent_write` in `kernel/cgroup/cgroup-v1.c`, where cgroups v1 `release_agent` handling can allow privilege escalation and unexpected namespace-isolation bypass under certain circumstances.
- **Operator takeaway** — during container, Kubernetes, CI-runner, and appliance assessments, treat writable cgroup v1 control files and privileged capability sets as an escape-path precondition, not as routine hardening trivia.

## When to use this check

Use this when the rules of engagement include container escape validation, CI runner breakout assessment, Kubernetes workload review, appliance shell validation, or post-exploitation boundary testing from an already-authorized low-privilege shell inside a container.

Good targets:

- self-hosted CI runners that execute untrusted jobs;
- Kubernetes pods with `privileged: true`, broad Linux capabilities, or host namespace joins;
- Docker/Podman workloads launched with `--privileged`, `--cap-add SYS_ADMIN`, or host mounts;
- containers on older Linux distributions or vendor appliances where kernel backports are unclear.

Do not run write-based exploit payloads against production. The validation below is designed to prove the dangerous preconditions without modifying cgroup control files.

## Read-only recon from inside a container

```bash
# Identity and namespace context.
id
hostname
cat /proc/1/cgroup
readlink /proc/1/ns/user /proc/1/ns/mnt /proc/1/ns/pid 2>/dev/null

# Kernel and cgroup mode.
uname -a
findmnt -t cgroup,cgroup2 2>/dev/null || mount | grep -E 'type cgroup|type cgroup2'

# Capability signal. If capsh is unavailable, keep the /proc status values.
capsh --print 2>/dev/null || true
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status

# cgroup v1 release_agent presence and permissions; read-only inspection.
find /sys/fs/cgroup -maxdepth 3 -name release_agent -exec sh -c 'for f; do printf "%s " "$f"; ls -l "$f"; done' sh {} + 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release -exec sh -c 'for f; do printf "%s " "$f"; ls -l "$f"; done' sh {} + 2>/dev/null
```

High-signal evidence:

- cgroup v1 mounts exist inside the container;
- a `release_agent` file is visible in a cgroup hierarchy;
- the current container identity can write relevant cgroup control files, or the file mode/ownership suggests it could under the tested principal;
- the container has `CAP_SYS_ADMIN`, runs privileged, joins host namespaces, or can mount cgroups;
- the kernel is in an affected range or patch status cannot be proven from vendor backports.

## Host-side container launch and Kubernetes checks

When host or cluster API access is in scope, prefer configuration proof over live escape attempts.

### Docker / containerd hosts

```bash
# Identify risky launch settings without changing containers.
docker ps --format '{{.ID}} {{.Image}} {{.Names}}'
docker inspect <container_id> \
  --format 'Privileged={{.HostConfig.Privileged}} CapAdd={{.HostConfig.CapAdd}} SecurityOpt={{.HostConfig.SecurityOpt}} Binds={{.HostConfig.Binds}} CgroupnsMode={{.HostConfig.CgroupnsMode}}'

# Kernel/cgroup context on the host.
uname -a
findmnt -t cgroup,cgroup2
```

Report `Privileged=true`, `CAP_SYS_ADMIN`, host cgroup mounts, host PID/user namespace joins, or writable host paths as escape-enabling context. Do not include secrets from bind mounts in evidence.

### Kubernetes clusters

```bash
# Review pod security context and host namespace joins.
kubectl get pod -A -o json | jq -r '
  .items[] |
  [.metadata.namespace, .metadata.name,
   (.spec.hostPID // false), (.spec.hostIPC // false), (.spec.hostNetwork // false),
   ((.spec.containers[]?.securityContext.privileged // false) | tostring),
   ((.spec.containers[]?.securityContext.capabilities.add // []) | join(","))] |
  @tsv'

# Locate workloads likely to expose cgroup or host filesystem boundaries.
kubectl get pod -A -o json | jq -r '
  .items[] |
  select((.spec.volumes[]?.hostPath.path // "") | test("^/(sys|proc|var/run|var/lib|etc|/)?")) |
  [.metadata.namespace, .metadata.name, (.spec.volumes[]?.hostPath.path // "")] | @tsv'
```

If `jq` is unavailable, capture the pod YAML for the in-scope workload and review `securityContext`, `hostPID`, `hostIPC`, `hostNetwork`, `hostPath`, and capability additions manually.

## Safe validation boundary

A strong non-destructive finding can stop at precondition proof:

1. The workload runs on a kernel version or vendor build where CVE-2022-0492 patch status is absent or affected.
2. cgroup v1 `release_agent` is present and reachable from the container context.
3. The workload has the capabilities or mount access normally required to manipulate cgroup control files.
4. The workload is in a trust zone where container breakout would cross an explicit authorization boundary, such as CI job to runner host or pod to node.

Only perform a full exploit in an isolated lab node or disposable target that the customer explicitly approved for destructive boundary testing. If full proof is required, use a benign canary artifact such as writing a fixed string to a temporary lab file, never credential access, host persistence, or lateral movement.

## Reporting heuristics

- Lead with the boundary crossed: “container workload can satisfy cgroup v1 `release_agent` escape preconditions,” not only “host has CVE-2022-0492.”
- Include kernel version, distribution/backport evidence, container runtime, cgroup mode, capability set, and exact cgroup file permissions.
- Separate config risk from exploit proof: privileged container plus writable cgroup files is high-signal even if you did not execute a payload.
- For Kubernetes, include namespace, service account, pod security context, relevant volume mounts, and whether the workload is reachable by untrusted users or CI jobs.
- Keep evidence minimal: no host secrets, service-account tokens, cloud metadata, or production file contents.

## Notes on skipped and unchanged sources

- CISA KEV also added CVE-2025-48595 for Android Framework integer overflow on 2026-06-02. It was not promoted because the available feed detail did not add a durable Skillz Wiki operator workflow beyond mobile patch/exposure tracking.
- GitHub Advisory Database latest items after the prior run were already processed Ech0 updates or generic application advisories that did not add a new replayable operator primitive.
- PortSwigger stayed on the Top 10 web hacking techniques of 2025; ProjectDiscovery stayed on the Neo agent-architecture post; GitHub Security Blog, Trail of Bits, and Disclosed had no new promotable offensive-operator delta.
