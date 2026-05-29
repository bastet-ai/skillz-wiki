# authentik SAML wrapping, CC-Tweaked NAT64 SSRF, and Keras model-loading boundary batch

Source: GitHub Security Advisories REST fallback, updated 2026-05-29: [GHSA-c3m2-jqmq-pvp3](https://github.com/advisories/GHSA-c3m2-jqmq-pvp3) / CVE-2026-47201, [GHSA-5jh9-2h63-pw4q](https://github.com/advisories/GHSA-5jh9-2h63-pw4q) / CVE-2026-47695, [GHSA-36fq-jgmw-4r9c](https://github.com/advisories/GHSA-36fq-jgmw-4r9c) / CVE-2025-9906, and [GHSA-c9rc-mg46-23w3](https://github.com/advisories/GHSA-c9rc-mg46-23w3) / CVE-2025-8747.

This batch is durable because it captures reusable offensive validation patterns: SAML XML signature wrapping where the verified node and consumed identity node diverge, private-network SSRF filters that miss NAT64 embeddings, and ML model-loader safe-mode bypasses that turn apparently safe `.keras` artifacts into file-write or code-execution primitives.

## What changed

- **authentik SAML Source XML signature wrapping** — authentik SAML Source ACS validation could accept a signature over one assertion or response while later consuming identity data from a different forged assertion. An attacker with any valid upstream IdP account and a captured signed SAML response could authenticate as a victim federated user or as a matched local user when email/username matching is enabled.
- **CC-Tweaked NAT64 SSRF bypass** — CC-Tweaked's `http.request` and `http.websocket` private-address block used Java `InetAddress` classification methods that did not treat `64:ff9b::/96` NAT64 addresses as private. On NAT64-routed IPv6-capable hosts, Lua code could reach internal IPv4 targets by encoding them inside NAT64 IPv6 literals.
- **Keras safe-mode model-loading bypass** — Keras `<3.11.0` allowed crafted `.keras` archives to reach unsafe deserialization despite `safe_mode=True`, including config-ordering that re-enabled unsafe deserialization before Lambda loading.
- **Keras internal-function reuse bypass** — Keras `>=3.0.0,<3.11.0` could be abused through trusted internal module functionality, such as `keras.utils.get_file`, to perform arbitrary file overwrite and in many workflows pivot to code execution when a target loads an untrusted model.

## Operator triage

1. **Find federated authentik deployments:** prioritize authentik instances using SAML Source for upstream federation, especially where user matching by email or username is enabled and the ACS endpoint is reachable from user browsers.
2. **Confirm the SAML signing profile:** the strongest authentik cases are signed assertions or signed responses without signed assertions where signature verification and consumed identity selection can diverge.
3. **Map scriptable CC-Tweaked surfaces:** look for public or shared Minecraft/CC-Tweaked environments where untrusted users can run Lua and where the server is deployed in IPv6-only, dual-stack, AWS, GCP, or NAT64-routed networks.
4. **Treat NAT64 as a filter-differential, not a scanner:** focus on one controlled callback or lab internal service proving private-target reachability through `64:ff9b::/96`.
5. **Trace ML artifact trust boundaries:** Keras impact depends on workflows that load models from user uploads, notebooks, marketplace/model-hub downloads, CI artifacts, or agent-generated experiment outputs.
6. **Separate model parsing from execution impact:** reports are strongest when they prove the target process loads the crafted archive automatically or as part of a normal user-controlled workflow.

## Replayable validation boundaries

### authentik SAML Source wrapping check

- **Use consenting lab identities:** create two test users at the upstream IdP and authenticate normally as the attacker-controlled account.
- **Capture only your own SAML response:** preserve the original signed response as the trusted signature source; do not intercept another user's traffic.
- **Forge a second assertion in a disposable lab response:** modify only a lab copy so the valid signature still verifies over the attacker's signed node while authentik consumes victim-style identifiers from the forged node.
- **Stop at login proof:** demonstrate session creation or username/email mapping for a test victim account; do not access real user data.
- **Record parser behavior:** include authentik version, SAML Source settings, signing mode, matching mode, ACS endpoint, and which XML node was signed versus consumed.

### CC-Tweaked NAT64 SSRF check

- **Verify routing first:** document whether the host network routes `64:ff9b::/96` or another NAT64 prefix to IPv4.
- **Start with a tester-owned callback:** issue `http.request("http://[64:ff9b::<callback-ip-hex>]/")` from Lua and compare it with a direct blocked private IPv4 attempt.
- **Use one lab-only internal target:** if authorized, run a benign HTTP service on an internal IPv4 address and encode it as a NAT64 literal to prove filter bypass.
- **Avoid metadata harvesting:** do not query cloud metadata or enumerate internal ports on production systems. A controlled callback plus blocked-direct/allowed-NAT64 differential is enough.
- **Report the final dial address:** include the Lua call, resolved `InetAddress` family, CC-Tweaked version, cloud/network NAT64 configuration, and response evidence.

### Keras `.keras` safe-mode bypass check

- **Use an isolated loader:** reproduce in a disposable virtualenv/container with vulnerable Keras and no sensitive credentials.
- **Craft a harmless archive marker:** use a payload that writes a canary file in a temp directory or performs a tester-owned callback, never destructive commands.
- **Exercise the real load path:** call the same `keras.models.load_model(..., safe_mode=True)` or application wrapper used by the target workflow.
- **Prove safe-mode drift:** show that the archive config or internal-function gadget changes behavior before unsafe deserialization or file write occurs.
- **Tie to artifact ingestion:** include where the model can come from, whether the target auto-loads it, and what principal executes the loader.

## Reporting heuristics

- For authentik, frame the bug as identity-node confusion after signature verification, not merely "SAML is misconfigured." Include the signed node, consumed node, matching mode, and test-user impact.
- For CC-Tweaked, show a private-address deny-list discrepancy: direct private IPv4 blocked, NAT64-embedded private IPv4 allowed, same destination under authorized control.
- For Keras, include vulnerable version, `safe_mode=True` evidence, the exact model-ingestion route, and the benign effect produced by the archive.
- Keep all proofs scoped to authorized lab identities, controlled callbacks, and synthetic model artifacts.

## Notes on skipped items from this scan

- Langflow CORS/session refresh to token theft and RCE (`GHSA-577h-p2hh-v4mv` / CVE-2025-34291) was reviewed as already reflected in the May 21 Langflow KEV guidance.
- go-tuf duplicate key-ID threshold counting, Keylime UUID reuse, vantage6 username-discovery lockout discrepancy, RPLY predictable tempfiles, protobuf legacy buffer overflow, and old Zope DoS material were reviewed as stale, low-detail, prerequisite-heavy, availability-oriented, or not distinct enough for a new Skillz operator page.
- zeroconf cache/exception-retention memory exhaustion remained availability-only and was not promoted.
- CISA KEV stayed catalog `2026.05.29` with CVE-2026-0257 already reflected in the prior Skillz update. PortSwigger, ProjectDiscovery, GitHub Security Blog, Trail of Bits `/feed.xml`, and Disclosed had no separate promotable deltas in this pass.
