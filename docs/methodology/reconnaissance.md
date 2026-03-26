# Reconnaissance

Reconnaissance in Skillz Wiki is about turning scope into a prioritized asset inventory without burning time or causing unnecessary noise.

## Objectives

- Confirm what is in scope.
- Map domains, hosts, services, and exposed applications.
- Identify technologies, trust boundaries, and likely authentication paths.
- Produce enough evidence to drive focused validation instead of random scanning.

## Default sequence

1. Start with written scope and exclusions.
2. Collect passive data from official docs, certificate logs, public repos, and existing program context.
3. Use targeted active discovery only after passive sources stop yielding useful expansion.
4. Normalize findings into a single working inventory.
5. Mark likely priorities: auth endpoints, admin surfaces, internet-facing services, and third-party dependencies.

## Recommended skills

- [DNS Enumeration](../skills/dns-enumeration.md)
- [Nmap Scanning](../skills/nmap-scanning.md)

## Deliverables

- Asset inventory with source attribution
- Service map with hostnames, ports, and technologies
- Candidate attack paths worth validating next
- Notes on rate limits, exclusions, and sensitive surfaces
