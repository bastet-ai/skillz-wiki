# Recon Workflow Overview

Skillz Wiki splits content into two layers:

- **Skills** teach one tool or capability in a way an agent can reuse directly.
- **Recon workflows** show how those skills fit into asset discovery and prioritization.
- **Exploit paths** capture concrete attack chains that are worth replaying in authorized environments.

## Default flow

1. **Scope first**: confirm the program boundary, exclusions, and safe proof limits.
2. **Asset expansion**: grow the host and service inventory through passive discovery and narrow active probing.
3. **Surface shaping**: identify auth flows, admin panels, APIs, exposed client bundles, and likely trust boundaries.
4. **Hypothesis selection**: turn the highest-value surfaces into a short list of concrete exploit paths.
5. **Validation**: prove the path with minimal-impact, reproducible commands and preserve the output needed to replay it later.

## Operating rules

- Start with scope, rate limits, and handling constraints.
- Prefer passive collection before active discovery.
- Keep every notable command reproducible and attributable.
- Separate confirmed behavior from inferred risk.
- Stop escalating when the engagement or program rules stop.

## Recommended building blocks

- Use the [DNS Enumeration](../skills/dns-enumeration.md) skill to expand domain scope safely.
- Use the [HTTP Probing with httpx](../skills/httpx.md) skill to turn discovered hosts into a prioritized web surface.
- Use the [Nmap Scanning](../skills/nmap-scanning.md) skill to convert hosts into concrete services.
- Use [Client-Side Analysis](client-side-analysis.md) when web applications expose JavaScript-heavy entry points and third-party integrations.
