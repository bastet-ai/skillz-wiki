# Playbook Overview

Skillz Wiki splits content into two layers:

- **Skills** teach one tool or capability in a way an agent can reuse directly.
- **Playbooks** show how those skills fit into an assessment flow.

## Default flow

1. **Reconnaissance**: build an evidence-backed asset map before touching deeper actions.
2. **Vulnerability assessment**: turn exposed services and application paths into testable hypotheses.
3. **Exploitation**: validate impact with the smallest safe proof possible.
4. **Post-exploitation**: only when explicitly authorized, demonstrate blast radius and cleanup requirements.
5. **Reporting**: preserve commands, artifacts, timestamps, and remediation-ready writeups.

## Operating rules

- Start with scope, rate limits, and handling constraints.
- Prefer passive collection before active discovery.
- Keep every notable command reproducible and attributable.
- Separate confirmed behavior from inferred risk.
- Stop escalating when the engagement or program rules stop.

## Recommended pairings

- Use the [DNS Enumeration](../skills/dns-enumeration.md) skill to expand domain scope safely.
- Use the [Nmap Scanning](../skills/nmap-scanning.md) skill to convert hosts into concrete services.
- Use the [Web Application Checklist](../checklists/web-applications.md) once services become reachable application surfaces.
- Use [Reporting Best Practices](../best-practices/reporting.md) as the final quality gate before publishing findings.
