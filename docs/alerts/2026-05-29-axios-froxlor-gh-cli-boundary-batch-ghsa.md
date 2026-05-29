# Axios prototype-pollution, Froxlor shell, and GitHub CLI token-boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-35jp-ww65-95wh](https://github.com/advisories/GHSA-35jp-ww65-95wh) / CVE-2026-44494, [GHSA-3g43-6gmg-66jw](https://github.com/advisories/GHSA-3g43-6gmg-66jw) / CVE-2026-44495, [GHSA-pjwm-pj3p-43mv](https://github.com/advisories/GHSA-pjwm-pj3p-43mv) / CVE-2026-44492, [GHSA-898c-q2cr-xwhg](https://github.com/advisories/GHSA-898c-q2cr-xwhg) / CVE-2026-44490, [GHSA-654m-c8p4-x5fp](https://github.com/advisories/GHSA-654m-c8p4-x5fp) / CVE-2026-44489, [GHSA-gcv3-5v9q-fmhh](https://github.com/advisories/GHSA-gcv3-5v9q-fmhh) / CVE-2026-41235, [GHSA-mq5v-pxpm-8jw2](https://github.com/advisories/GHSA-mq5v-pxpm-8jw2) / CVE-2026-41236, [GHSA-j6fm-9rfm-j5hx](https://github.com/advisories/GHSA-j6fm-9rfm-j5hx) / CVE-2026-41237, and [GHSA-8xvp-7hj6-mcj9](https://github.com/advisories/GHSA-8xvp-7hj6-mcj9) / CVE-2026-48501.

This batch is durable because it gives three reusable operator patterns: prototype-pollution gadgets in outbound HTTP clients, panel-to-host privilege boundaries in hosting control panels, and supply-chain verification clients leaking tokens to non-API mirrors.

## What changed

- **Axios prototype-pollution gadgets** — affected npm ranges include `axios >=1.0.0 <1.16.0`, older `0.x` releases for several issues, and `axios 1.15.2` for an incomplete nested-object proxy fix. Polluted inherited config can steer Node HTTP traffic through an attacker-controlled proxy, inject headers, break proxy bypass logic for IPv4-mapped IPv6 loopback/metadata hosts, or alter response transforms when a separate same-process prototype-pollution primitive exists.
- **Froxlor FTP shell assignment and SSH key sync boundaries** — Froxlor `2.3.6` lets shell-enabled customer accounts submit shells outside `system.available_shells` and can later append customer-supplied SSH keys through a root-owned sync path that follows `~/.ssh/authorized_keys` symlinks. The DNS record validation follow-up also leaves zone-file injection edge cases for LOC/TLSA-style record content.
- **GitHub CLI TUF mirror token boundary** — `gh <=2.92.0` could attach GitHub or enterprise tokens to TUF repository mirror requests used by `gh attestation`, `gh release verify`, and `gh release verify-asset`, including `tuf-repo.github.com`, `tuf-repo-cdn.sigstore.dev`, and Azure Blob Storage hosts.

## Operator triage

1. **Axios dependency graph:** locate applications using axios in Node services, SSR handlers, CLIs, build agents, webhook processors, or browser bundles where user-controlled parsing can pollute `Object.prototype` before outbound requests are made.
2. **Prototype-pollution pairing:** do not treat axios as the pollution source. Pair the advisory with confirmed upstream primitives such as unsafe deep merge, query parsing, YAML/JSON import, template context merge, or plugin configuration merge in the same process.
3. **Outbound trust boundary:** prioritize axios calls that carry bearer tokens, cookies, `auth`, webhook secrets, metadata-service requests, internal service URLs, or release/build artifact verification traffic.
4. **Froxlor exposure:** search for Froxlor customer panels where `system.allow_customer_shell=1`, affected customer accounts have `shell_allowed=1`, `nssextrausers` is enabled, and FTP users map to host accounts with customer-controlled home directories.
5. **GitHub CLI usage:** check developer laptops and CI runners that invoke `gh attestation`, `gh release verify`, or `gh release verify-asset` while authenticated to `github.com` or with `GH_ENTERPRISE_TOKEN` / `GITHUB_ENTERPRISE_TOKEN` set.

## Replayable validation boundaries

### Axios client-gadget checks

- **Safe pollution marker:** in a disposable lab process using the scoped axios version, set only harmless marker values on `Object.prototype` and send requests to a tester-owned HTTP server/proxy. Capture whether inherited `proxy`, `common` header buckets, or `transformResponse`-style keys are consumed. Remove polluted keys immediately after each request.
- **Proxy steering proof:** with an authorized test proxy, prove that an inherited `proxy` object routes axios traffic through the proxy even when the application did not set an own `config.proxy`. Record the request path and headers, but do not capture real production credentials.
- **NO_PROXY differential:** compare `http://127.0.0.1/`, `http://[::1]/`, and `http://[::ffff:127.0.0.1]/` against a lab proxy with `NO_PROXY=127.0.0.1,localhost,::1`. The useful proof is proxy-use disagreement for IPv4-mapped IPv6, especially for loopback or metadata-service allow/deny boundaries.
- **Header injection proof:** inject a benign custom header such as `X-Skillz-Marker: yes` through inherited defaults and verify it appears only on the tester-owned receiver. Avoid `Authorization`, `Cookie`, `Content-Length`, or request-smuggling headers outside a contained lab.
- **Response-transform proof:** if and only if the paired pollution primitive can create functions, demonstrate that the inherited transform sees request config and can change a lab response. If the primitive can only create JSON-like values, report the lower-impact crash/header behavior instead.

### Froxlor panel-to-host checks

- **Shell whitelist bypass:** from an authorized customer test account with shell delegation enabled, submit an FTP edit/add request that sets a shell value not present in `system.available_shells`, then confirm whether the panel stores it and whether the NSS rebuild propagates it to the generated host account database.
- **Symlink-following proof:** in a disposable Froxlor lab, replace the FTP user's `~/.ssh/authorized_keys` with a symlink to a tester-controlled canary file rather than `/root/.ssh/authorized_keys`. Submit an SSH key through the panel and wait for the root-owned sync task. Vulnerable behavior is append-through-symlink into the canary target.
- **DNS zone injection regression:** for LOC/TLSA validation, use a test zone and marker-only records to check whether embedded newlines or unbounded data survive validation and alter generated zone-file structure. Do not poison live DNS.

### GitHub CLI token-boundary checks

- **Host-scoped token audit:** in an isolated environment with a throwaway token, run the affected verification commands through a local HTTPS interception proxy or controlled DNS/TUF mirror harness and confirm whether `Authorization` is sent to non-API hosts.
- **Environment split:** test `github.com` login tokens separately from `GH_ENTERPRISE_TOKEN` / `GITHUB_ENTERPRISE_TOKEN` because the advisory describes different fallback behavior for GitHub subdomains and external mirror hosts.
- **CI evidence:** capture command invocation, `gh version`, relevant environment variables, and destination hosts. The report should show token egress to the wrong trust domain without exposing the token value.

## Reporting heuristics

- For axios findings, report the full chain: pollution source, polluted key, axios version, adapter/context, outbound destination, secret-bearing request class, and whether the proof is MITM routing, header injection, proxy bypass, transform execution, or crash-only.
- For Froxlor, separate panel authorization bypass from host privilege impact. Include customer prerequisites, shell settings, NSS/cron configuration, filesystem ownership, symlink behavior, and the exact generated file affected.
- For GitHub CLI, frame the issue as token origin versus request destination mismatch. Include the `gh` command family, token source, target mirror host, and whether the token was GitHub.com or GHES scoped.
- Avoid overclaiming: axios gadgets require a separate prototype-pollution primitive; Froxlor host escalation requires shell-enabled customer/home-directory control and the privileged sync path; GitHub CLI leakage depends on affected verification commands being run while authenticated.

## Notes on skipped items from this scan

- CISA KEV stayed on catalog `2026.05.28`; its newest Nx Console, TanStack, Daemon Tools Lite, LiteSpeed, Drupal, Langflow, and Trend Micro entries were already reflected or previously triaged for Skillz operator value.
- PortSwigger stayed on the Top 10 web hacking techniques of 2025, ProjectDiscovery stayed on already-covered Neo/Nuclei/DAST material, GitHub Security Blog remained GHES signing-key rotation / IR-oriented, Trail of Bits `/feed.xml` returned 404, and Disclosed DNS still failed.
