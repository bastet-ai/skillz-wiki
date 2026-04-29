# Nginx-UI cluster proxy SSRF to internal services (GHSA-wr32-99hh-6f35)

**Signal:** GitHub Security Advisory published **2026-04-29**. Nginx-UI cluster proxy middleware can be abused for server-side request forgery.

## What it is
Nginx-UI versions `<= 2.3.4` expose cluster proxy behavior that can reach internal services. In deployments where Nginx-UI is reachable by lower-trust users, compromised accounts, or the internet, the proxy can become a pivot into loopback, RFC1918 networks, metadata services, control planes, and admin-only HTTP APIs.

References:

- <https://github.com/advisories/GHSA-wr32-99hh-6f35>
- <https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-wr32-99hh-6f35>

## Triage
1. Find Nginx-UI instances and confirm version, exposure, authentication method, and role model.
2. Review cluster proxy configuration and any route that accepts host, node, upstream, URL, or path input.
3. Prioritize instances running on hosts with access to Nginx admin sockets, cloud metadata, service discovery, Kubernetes APIs, CI/CD, or internal dashboards.
4. Check whether Nginx-UI logs include requested proxy destinations.

## Mitigation
- Restrict Nginx-UI to a management network or VPN; do not expose it publicly.
- Disable cluster proxy functionality if not required.
- Add egress filtering from the Nginx-UI host/container: deny loopback, link-local, metadata, RFC1918, and control-plane addresses unless explicitly needed.
- Enforce a strict destination allowlist for cluster nodes and canonicalize DNS/IPs after redirects.
- Rotate credentials if logs show proxy access to sensitive internal endpoints.

## Detection ideas
- Hunt for proxy requests targeting `127.0.0.1`, `localhost`, `169.254.169.254`, Kubernetes service IPs, Docker sockets/proxies, and cloud metadata hostnames.
- Alert on Nginx-UI outbound connections to destinations outside the approved cluster-node list.
- Review unusual admin actions shortly after proxy errors, 3xx redirects, or connection attempts to internal-only services.

## Durable lesson
Administrative UIs often sit exactly where SSRF hurts most. Cluster proxy features need destination allowlists and host-level egress policy, not just UI authentication.
