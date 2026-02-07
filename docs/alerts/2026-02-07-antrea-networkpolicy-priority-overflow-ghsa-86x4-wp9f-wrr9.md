# 2026-02-07 — Antrea NetworkPolicy enforcement-order bug via integer overflow (GHSA-86x4-wp9f-wrr9)

GitHub advisory: <https://github.com/advisories/GHSA-86x4-wp9f-wrr9>

Upstream advisory: <https://github.com/antrea-io/antrea/security/advisories/GHSA-86x4-wp9f-wrr9>

## Summary

Antrea’s NetworkPolicy priority assignment uses `uint16` arithmetic for OpenFlow priority calculation.

With a sufficiently large set of Antrea NetworkPolicies (ANP / ACNP) across varying priority values, **integer overflow** can cause **incorrect OpenFlow priority ordering**, resulting in **unexpected allow/deny outcomes**.

In practice, this can become a security boundary issue when teams assume:

- “higher-priority policy always wins”, and/or
- “lower-privilege users can’t override higher-priority tiers”.

## Who is at risk

You are affected if you use **Antrea NetworkPolicies** (ANP/ACNP). Deployments that **only** use upstream Kubernetes NetworkPolicies (and do not enable Antrea’s extensions) are **not affected** per the advisory.

Higher risk if:

- You delegate policy authoring to multiple teams/roles, especially using **tiers**.
- Your enforcement expectations rely on tier boundaries preventing override.

## Mitigation

1. **Upgrade Antrea**
   - Upgrade to a patched version:
     - **v2.5.0**, or
     - **v2.4.3**, or
     - **v2.3.2**

2. **Reduce blast radius until you can patch** (defense-in-depth)
   - Minimize the number of ANP/ACNP objects and priority permutations.
   - Limit who can create/modify ANP/ACNP and which tiers they can write to.

3. **Validate intent with traffic tests**
   - For critical deny rules (e.g., admin APIs, sensitive services), validate enforcement with:
     - synthetic probes from representative pods/namespaces
     - canary policies (explicit denies) and alerting on unexpected allows

## Detection / hunt

- Watch for sudden “policy doesn’t seem to apply” incidents correlated with large policy rollouts.
- Audit RBAC for who can create ANP/ACNP and which tiers they can target.
- If you have OpenFlow visibility, spot-check priorities for unexpected ordering after policy changes.
