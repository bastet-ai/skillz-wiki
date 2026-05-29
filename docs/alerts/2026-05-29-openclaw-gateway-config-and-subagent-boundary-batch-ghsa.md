# OpenClaw gateway config and subagent control-boundary batch

**Signal:** GitHub Security Advisories updated **2026-05-29** with OpenClaw control-plane boundary fixes. These are useful to operators because they describe repeatable validation patterns for agent platforms: model-driven config writes, UI bootstrap disclosure, inherited child-session constraints, command-owner derivation, and media-root containment.

## Advisories covered

- **Gateway config mutation guard fail-open** — [GHSA-cwj3-vqpp-pmxr](https://github.com/advisories/GHSA-cwj3-vqpp-pmxr): `openclaw < 2026.4.23`; fixed in `2026.4.23`. The agent-facing `gateway config.apply` / `config.patch` guard used a denylist of protected paths, leaving newly added sensitive config subtrees writable by a model-driven tool call.
- **Control UI bootstrap config missing Gateway auth** — [GHSA-93rg-2xm5-2p9v](https://github.com/advisories/GHSA-93rg-2xm5-2p9v): `openclaw <= 2026.4.21`; fixed in `2026.4.22`. The Control UI bootstrap config endpoint could expose bootstrap/config fields without a valid Gateway token when Gateway auth was enabled.
- **ACP child sessions missing inherited subagent envelope constraints** — [GHSA-q3jj-46pq-826r](https://github.com/advisories/GHSA-q3jj-46pq-826r) / CVE-2026-44997: `openclaw <= 2026.4.21`; fixed in `2026.4.22`. Restricted subagents could spawn ACP child sessions without carrying forward depth, child-count, control-scope, or target-agent restrictions.
- **Wildcard channel senders as command owners** — [GHSA-c28g-vh7m-fm7v](https://github.com/advisories/GHSA-c28g-vh7m-fm7v) / CVE-2026-44991: `openclaw <= 2026.4.20`; fixed in `2026.4.21`. Owner-enforced commands could inherit wildcard inbound sender policy when no explicit `commands.ownerAllowFrom` was configured.
- **Webchat audio local-file read without media-root containment** — [GHSA-gfg9-5357-hv4c](https://github.com/advisories/GHSA-gfg9-5357-hv4c): `openclaw <= 2026.4.14`; fixed in `2026.4.15`. Tool or model-controlled audio media URLs could be embedded from readable host-local audio-like files without the usual local-root check.

## Operator validation workflow

Use this during an authorized assessment of an agent runtime or OpenClaw deployment. Keep proofs non-destructive and prefer marker values over real secrets.

1. **Version and exposure inventory**
   - Record OpenClaw version, exposed Gateway/Control UI origins, enabled channel plugins, ACP harness availability, and whether webchat is reachable by untrusted users.
   - Prioritize deployments older than `2026.4.23`, especially ones that allow model/tool access to owner-only Gateway helpers, wildcard channel senders, or ACP delegation.

2. **Gateway config write boundary**
   - Enumerate which config paths the agent-facing gateway tool is allowed to mutate.
   - In a disposable test config, attempt a harmless marker write to one known safe prompt/model setting and one security-sensitive class such as command policy, network/proxy/TLS behavior, credential forwarding, telemetry/hooks, runtime tool policy, or memory/indexing surfaces.
   - A fixed deployment should fail closed for anything outside the narrow agent-tunable allowlist before the mutation RPC reaches persistence.

3. **Bootstrap read boundary**
   - With Gateway auth enabled, request the Control UI bootstrap/config endpoint without a token, with an invalid token, and with a valid token.
   - The unauthenticated and invalid-token cases should fail before returning bootstrap fields. Capture only field names/classes in reports; do not copy real secrets into evidence.

4. **Subagent-to-ACP inheritance boundary**
   - Create a restricted subagent profile in a lab: low max-depth, small child cap, narrow control scope, and restricted ACP target list.
   - From that restricted context, attempt to spawn ACP children that exceed depth, count, target-agent, or control-scope constraints.
   - A fixed deployment should persist inherited envelope fields and reject violations at spawn/control time.

5. **Channel command-owner boundary**
   - Review channel configs for `commands.enforceOwnerForCommands: true`, `allowFrom: ["*"]`, and missing `commands.ownerAllowFrom`.
   - From a non-owner identity in an authorized test channel, try a benign owner-enforced command that has no side effects or targets a test-only resource.
   - The owner decision must come from explicit owner identity or operator-admin scope, not from broad inbound acceptance.

6. **Media-root containment boundary**
   - In a lab webchat, test model/tool-produced media references that look like local absolute paths, `file:` URLs, UNC paths, and allowed local-root media.
   - Fixed media embedding should reject untrusted local references unless they are explicitly rooted, authorized, size-capped, and typed for that media path.

## Reporting heuristics

- Treat **persistent config writes** as higher impact than one-shot tool misuse. Persistence can change future command execution, network egress, credential forwarding, hooks, telemetry, or policy after a restart.
- Treat **child-session envelope drift** as a delegation vulnerability even when the parent subagent was already restricted. The child is a fresh control surface and must inherit the restriction set explicitly.
- For **bootstrap/config disclosure**, report classes of exposed fields and whether they enable follow-on targeting, not just that an endpoint returned JSON.
- For **command-owner bugs**, include the exact channel policy combination that caused wildcard sender identity to become command authority.
- For **media local-file reads**, report the trust transition: untrusted model/tool output became a host filesystem read and webchat transcript disclosure.

## Durable lesson

Agent platforms need fail-closed gates at durable state and delegation boundaries. Do not rely on denylisted config paths, inherited channel allowlists, UI-only auth assumptions, or model-supplied media paths. Recompute authority at the final action: persistence, bootstrap read, child-session spawn, owner command execution, and host file read.
