# Netavark / Podman search-domain DNS confusion boundary

## Operator value

GitHub Advisory Database update [GHSA-rpcf-rmh6-42xr / CVE-2025-8283](https://github.com/advisories/GHSA-rpcf-rmh6-42xr) describes a Podman / Netavark container DNS regression where the `dns.podman` search domain was not added for bridge-network container name resolution. If the container inherits host search domains and one of those domains has a record matching another container's hostname, application traffic intended for a same-network container can resolve to an unexpected external server.

The durable offensive lesson: during authorized container and internal-app assessments, treat short service names as a trust boundary. A target that connects to `postgres`, `redis`, `api`, or `metadata` may not always hit the sibling container the operator expects; host search-domain leakage and wildcard DNS can turn internal service-name assumptions into traffic redirection or credential-capture opportunities in a lab.

## Affected surface

| Surface | Affected versions noted by GHSA | Fixed version | Boundary to test |
| --- | --- | --- | --- |
| Netavark bridge-network DNS for Podman containers | `netavark < 1.15.1` | `1.15.1` | short container/service hostname to resolver search-domain behavior |

The upstream fix reintroduced Podman's default DNS search domain in bridge-network DNS responses: [containers/netavark commit `068abc869b736a03a947b5419c102da73830e882`](https://github.com/containers/netavark/commit/068abc869b736a03a947b5419c102da73830e882), via [PR #1256](https://github.com/containers/netavark/pull/1256). The related Podman issue shows the practical symptom: `pgadmin` trying to reach `postgres` by container name after a Netavark update: [containers/podman#26198](https://github.com/containers/podman/issues/26198).

## Recon workflow

1. Confirm scope permits container networking tests, DNS records under a controlled domain, and packet/log collection from test containers.
2. Inventory Podman / Netavark versions on developer workstations, CI runners, and self-hosted container hosts:

   ```bash
   podman version 2>/dev/null || true
   netavark --version 2>/dev/null || true
   rpm -q netavark podman 2>/dev/null || true
   dpkg-query -W netavark podman 2>/dev/null || true
   ```

3. Review container configuration for short-name service dependencies:

   ```bash
   grep -R "host=.*\b\|POSTGRES_HOST\|REDIS_HOST\|DATABASE_URL\|http://[a-z0-9_-]\+[:/]" \
     compose.y*ml docker-compose.y*ml Containerfile Dockerfile .env* 2>/dev/null
   ```

4. Capture resolver context from a disposable container on the target-style network:

   ```bash
   podman run --rm --network TARGET_NET alpine:3.20 sh -lc \
     'cat /etc/resolv.conf; getent hosts postgres || true; getent hosts redis || true'
   ```

5. Prioritize environments where the host search domain is attacker-controllable, partner-controlled, or program-controlled for testing, and where applications connect to high-value services by bare hostname.

## Safe validation pattern

Use only a lab or explicitly authorized test network. The goal is to prove name-resolution confusion, not to intercept production credentials.

1. Choose a harmless short service name used by the compose stack, such as `postgres`.
2. Configure the host/container resolver search domain to a domain you control, such as `skillz-lab.example`, and publish an A/AAAA record for `postgres.skillz-lab.example` pointing to an owned listener.
3. Start two containers on the same Podman bridge network: an application/client container and the intended service container named `postgres`.
4. From the client container, compare fully qualified and short-name resolution:

   ```bash
   podman run --rm --network TARGET_NET alpine:3.20 sh -lc '
     apk add --no-cache bind-tools >/dev/null
     echo "--- resolv.conf"; cat /etc/resolv.conf
     echo "--- short name"; getent hosts postgres || true; nslookup postgres || true
     echo "--- podman FQDN"; getent hosts postgres.dns.podman || true
     echo "--- controlled search-domain FQDN"; getent hosts postgres.skillz-lab.example || true
   '
   ```

5. If the short name resolves to the controlled external record instead of the same-network container, make one inert connection to an owned listener and stop:

   ```bash
   nc -lvnp 15432
   # from the test container only
   printf 'skillz-netavark-dns-canary\n' | nc -w 3 postgres 15432 || true
   ```

Report only the resolver behavior and canary connection. Do not proxy real database traffic, collect credentials, or alter production DNS.

## Evidence to capture

- Netavark and Podman versions, package manager evidence, and network driver mode.
- `/etc/resolv.conf` from the test container, including search-domain order.
- The tested short hostname, intended container identity, and controlled DNS record used for the canary.
- `getent` / `nslookup` output comparing short name, Podman FQDN, and controlled search-domain FQDN.
- Listener log containing only the inert canary string and source metadata needed to prove path reachability.
- Cleanup evidence: removed DNS canary record, stopped listener, deleted disposable containers.

## Report framing

Frame this as a container DNS trust-boundary issue:

- Application code assumes a bare service name targets a sibling container.
- Resolver search-domain behavior can cause that bare name to resolve outside the Podman network.
- Impact depends on whether the misdirected protocol sends secrets, session tokens, database credentials, or internal requests on first contact.

Keep findings bounded to authorized labs or explicit test containers, and separate version reachability from demonstrated traffic redirection.

## Sources

- GitHub Advisory Database: [GHSA-rpcf-rmh6-42xr / CVE-2025-8283](https://github.com/advisories/GHSA-rpcf-rmh6-42xr)
- Red Hat CVE reference: [CVE-2025-8283](https://access.redhat.com/security/cve/CVE-2025-8283)
- Podman issue: [containers/podman#26198](https://github.com/containers/podman/issues/26198)
- Netavark PR: [containers/netavark#1256](https://github.com/containers/netavark/pull/1256)
- Netavark fix commit: [`068abc869b736a03a947b5419c102da73830e882`](https://github.com/containers/netavark/commit/068abc869b736a03a947b5419c102da73830e882)
